const path = require("path");
const crypto = require("crypto");
const dns = require("dns").promises;
const net = require("net");
const express = require("express");
const session = require("express-session");
const Database = require("better-sqlite3");
const cheerio = require("cheerio");

const app = express();

function parseBooleanEnv(value, fallback) {
  if (value === undefined) return fallback;
  const normalized = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
}

function parseIntegerEnv(value, fallback, min, max) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    return fallback;
  }
  return parsed;
}

const PORT = parseIntegerEnv(process.env.PORT, 3000, 1, 65535);
const HOST = String(process.env.HOST || "127.0.0.1").trim() || "127.0.0.1";
const SESSION_SECRET = process.env.SESSION_SECRET || "change-me";
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "bookmarks.db");
const IS_PRODUCTION = process.env.NODE_ENV === "production";

const PASSWORD_MIN_LENGTH = parseIntegerEnv(process.env.PASSWORD_MIN_LENGTH, 12, 8, 256);
const DATA_KEY_LENGTH = 32;
const ENCRYPTED_PREFIX = "enc.v1";
const SESSION_MAX_AGE_MS = parseIntegerEnv(
  process.env.SESSION_MAX_AGE_MS,
  1000 * 60 * 60 * 12,
  1000 * 60,
  1000 * 60 * 60 * 24 * 30
);
const FETCH_TIMEOUT_MS = parseIntegerEnv(process.env.FETCH_TIMEOUT_MS, 8000, 1000, 60000);
const FETCH_BLOCK_PRIVATE_IPS = parseBooleanEnv(process.env.FETCH_BLOCK_PRIVATE_IPS, true);
const LOGIN_RATE_LIMIT_WINDOW_MS = parseIntegerEnv(
  process.env.LOGIN_RATE_LIMIT_WINDOW_MS,
  1000 * 60 * 15,
  1000,
  1000 * 60 * 60 * 24
);
const LOGIN_RATE_LIMIT_MAX = parseIntegerEnv(process.env.LOGIN_RATE_LIMIT_MAX, 10, 1, 1000);
const LOGIN_LOCKOUT_THRESHOLD = parseIntegerEnv(process.env.LOGIN_LOCKOUT_THRESHOLD, 5, 1, 1000);
const LOGIN_LOCKOUT_MS = parseIntegerEnv(
  process.env.LOGIN_LOCKOUT_MS,
  1000 * 60 * 15,
  1000,
  1000 * 60 * 60 * 24
);
const TRUST_PROXY = String(process.env.TRUST_PROXY || "").trim();
const COOKIE_SAMESITE_VALUE = String(process.env.COOKIE_SAMESITE || "lax").trim().toLowerCase();
const COOKIE_SAMESITE = ["lax", "strict", "none"].includes(COOKIE_SAMESITE_VALUE)
  ? COOKIE_SAMESITE_VALUE
  : "lax";
const SESSION_COOKIE_SECURE = IS_PRODUCTION || COOKIE_SAMESITE === "none";

if (SESSION_SECRET === "change-me") {
  console.warn("SESSION_SECRET is using the default value. Set a strong random secret.");
}

if (COOKIE_SAMESITE === "none" && !IS_PRODUCTION) {
  console.warn("COOKIE_SAMESITE=none usually requires HTTPS. Use with care outside production.");
}

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS lists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    position INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS bookmarks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    title TEXT NOT NULL,
    favicon TEXT,
    tags TEXT NOT NULL DEFAULT '',
    is_favorite INTEGER NOT NULL DEFAULT 0,
    position INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    list_id INTEGER,
    FOREIGN KEY (list_id) REFERENCES lists(id)
  );

  CREATE TABLE IF NOT EXISTS auth_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    password_salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    encryption_salt TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );
`);

const bookmarkColumns = db.prepare("PRAGMA table_info(bookmarks)").all();
if (!bookmarkColumns.some((col) => col.name === "list_id")) {
  db.exec("ALTER TABLE bookmarks ADD COLUMN list_id INTEGER");
}

const getAuthConfigStmt = db.prepare(
  `SELECT password_salt AS passwordSalt, password_hash AS passwordHash, encryption_salt AS encryptionSalt
   FROM auth_config
   WHERE id = 1`
);
const insertAuthConfigStmt = db.prepare(
  `INSERT INTO auth_config (id, password_salt, password_hash, encryption_salt, created_at, updated_at)
   VALUES (1, @passwordSalt, @passwordHash, @encryptionSalt, @createdAt, @updatedAt)`
);

const getAnyListStmt = db.prepare("SELECT id FROM lists ORDER BY position ASC, id ASC LIMIT 1");
const getMaxListPositionStmt = db.prepare("SELECT COALESCE(MAX(position), 0) AS maxPos FROM lists");
const insertListStmt = db.prepare("INSERT INTO lists (name, position) VALUES (?, ?)");
const listListsStmt = db.prepare("SELECT id, name, position FROM lists ORDER BY position ASC, id ASC");
const getListStmt = db.prepare("SELECT id, name, position FROM lists WHERE id = ?");

function ensureDefaultList() {
  const existing = getAnyListStmt.get();
  if (existing) return existing.id;
  const result = insertListStmt.run("General", 1);
  return Number(result.lastInsertRowid);
}

const defaultListId = ensureDefaultList();
db.prepare("UPDATE bookmarks SET list_id = ? WHERE list_id IS NULL").run(defaultListId);

const getMaxPositionByListStmt = db.prepare(
  "SELECT COALESCE(MAX(position), 0) AS maxPos FROM bookmarks WHERE list_id = ?"
);
const insertBookmarkStmt = db.prepare(
  `INSERT INTO bookmarks (url, title, favicon, tags, is_favorite, position, created_at, list_id)
   VALUES (@url, @title, @favicon, @tags, @isFavorite, @position, @createdAt, @listId)`
);
const listBookmarksStmt = db.prepare(
  `SELECT b.id, b.url, b.title, b.favicon, b.tags, b.is_favorite AS isFavorite,
          b.position, b.created_at AS createdAt, b.list_id AS listId, l.name AS listName
   FROM bookmarks b
   JOIN lists l ON l.id = b.list_id
   ORDER BY l.position ASC, b.position ASC, b.id ASC`
);
const listBookmarksByListStmt = db.prepare(
  "SELECT id, position FROM bookmarks WHERE list_id = ? ORDER BY position ASC, id ASC"
);
const getBookmarkStmt = db.prepare(
  `SELECT b.id, b.url, b.title, b.favicon, b.tags, b.is_favorite AS isFavorite,
          b.position, b.created_at AS createdAt, b.list_id AS listId, l.name AS listName
   FROM bookmarks b
   JOIN lists l ON l.id = b.list_id
   WHERE b.id = ?`
);
const listRawListsStmt = db.prepare("SELECT id, name FROM lists ORDER BY id ASC");
const listRawBookmarksStmt = db.prepare(
  "SELECT id, url, title, favicon, tags, created_at AS createdAt FROM bookmarks ORDER BY id ASC"
);
const updateListNameStmt = db.prepare("UPDATE lists SET name = ? WHERE id = ?");
const updateFavoriteStmt = db.prepare("UPDATE bookmarks SET is_favorite = ? WHERE id = ?");
const updateTagsStmt = db.prepare("UPDATE bookmarks SET tags = ? WHERE id = ?");
const updateBookmarkPositionStmt = db.prepare("UPDATE bookmarks SET position = ? WHERE id = ?");
const updateBookmarkListStmt = db.prepare("UPDATE bookmarks SET list_id = ?, position = ? WHERE id = ?");
const updateBookmarkFieldsStmt = db.prepare(
  "UPDATE bookmarks SET url = ?, title = ?, favicon = ?, tags = ?, created_at = ? WHERE id = ?"
);
const deleteBookmarkStmt = db.prepare("DELETE FROM bookmarks WHERE id = ?");
const shiftDownStmt = db.prepare(
  "UPDATE bookmarks SET position = position - 1 WHERE list_id = ? AND position > ?"
);
const loginAttemptState = new Map();

function b64Encode(input) {
  return Buffer.from(input).toString("base64");
}

function b64Decode(input) {
  return Buffer.from(String(input || ""), "base64");
}

function deriveScrypt(password, saltBuffer, keyLength = DATA_KEY_LENGTH) {
  return crypto.scryptSync(password, saltBuffer, keyLength, {
    N: 16384,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024
  });
}

function createPasswordRecord(password) {
  const passwordSalt = crypto.randomBytes(16);
  const encryptionSalt = crypto.randomBytes(16);
  const passwordHash = deriveScrypt(password, passwordSalt, DATA_KEY_LENGTH);

  return {
    passwordSalt: b64Encode(passwordSalt),
    passwordHash: b64Encode(passwordHash),
    encryptionSalt: b64Encode(encryptionSalt)
  };
}

function verifyPassword(password, authConfig) {
  try {
    const derived = deriveScrypt(password, b64Decode(authConfig.passwordSalt), DATA_KEY_LENGTH);
    const expected = b64Decode(authConfig.passwordHash);
    return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
  } catch {
    return false;
  }
}

function deriveDataKey(password, encryptionSalt) {
  return deriveScrypt(password, b64Decode(encryptionSalt), DATA_KEY_LENGTH);
}

function isEncryptedValue(value) {
  return typeof value === "string" && value.startsWith(`${ENCRYPTED_PREFIX}:`);
}

function encryptText(plaintext, dataKey) {
  const value = String(plaintext || "");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", dataKey, iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${ENCRYPTED_PREFIX}:${b64Encode(iv)}:${b64Encode(tag)}:${b64Encode(encrypted)}`;
}

function decryptText(ciphertext, dataKey) {
  const value = String(ciphertext || "");
  if (!isEncryptedValue(value)) {
    return value;
  }

  const parts = value.split(":");
  if (parts.length !== 4 || parts[0] !== ENCRYPTED_PREFIX) {
    throw new Error("Corrupt encrypted data");
  }

  const iv = b64Decode(parts[1]);
  const tag = b64Decode(parts[2]);
  const payload = b64Decode(parts[3]);
  const decipher = crypto.createDecipheriv("aes-256-gcm", dataKey, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(payload), decipher.final()]);
  return decrypted.toString("utf8");
}

function decryptBookmarkRow(row, dataKey) {
  const decrypted = {
    ...row,
    url: decryptText(row.url, dataKey),
    title: decryptText(row.title, dataKey),
    favicon: decryptText(row.favicon, dataKey),
    tags: decryptText(row.tags, dataKey),
    createdAt: decryptText(row.createdAt, dataKey)
  };

  if (Object.prototype.hasOwnProperty.call(row, "listName")) {
    decrypted.listName = decryptText(row.listName, dataKey);
  }

  return decrypted;
}

function decryptListRow(row, dataKey) {
  return {
    ...row,
    name: decryptText(row.name, dataKey)
  };
}

function migratePlaintextLists(dataKey) {
  const rows = listRawListsStmt.all();
  const toUpdate = rows.filter((row) => !isEncryptedValue(row.name));

  if (!toUpdate.length) return 0;

  const txn = db.transaction((items) => {
    for (const row of items) {
      const nextName = encryptText(row.name, dataKey);
      updateListNameStmt.run(nextName, row.id);
    }
  });

  txn(toUpdate);
  return toUpdate.length;
}

function migratePlaintextBookmarks(dataKey) {
  const rows = listRawBookmarksStmt.all();
  const toUpdate = rows.filter(
    (row) =>
      !isEncryptedValue(row.url) ||
      !isEncryptedValue(row.title) ||
      !isEncryptedValue(row.favicon) ||
      !isEncryptedValue(row.tags) ||
      !isEncryptedValue(row.createdAt)
  );

  if (!toUpdate.length) return 0;

  const txn = db.transaction((items) => {
    for (const row of items) {
      const nextUrl = isEncryptedValue(row.url) ? row.url : encryptText(row.url, dataKey);
      const nextTitle = isEncryptedValue(row.title) ? row.title : encryptText(row.title, dataKey);
      const nextFavicon = isEncryptedValue(row.favicon) ? row.favicon : encryptText(row.favicon, dataKey);
      const nextTags = isEncryptedValue(row.tags) ? row.tags : encryptText(row.tags, dataKey);
      const nextCreatedAt = isEncryptedValue(row.createdAt)
        ? row.createdAt
        : encryptText(row.createdAt, dataKey);
      updateBookmarkFieldsStmt.run(nextUrl, nextTitle, nextFavicon, nextTags, nextCreatedAt, row.id);
    }
  });

  txn(toUpdate);
  return toUpdate.length;
}

function migratePlaintextData(dataKey) {
  return migratePlaintextLists(dataKey) + migratePlaintextBookmarks(dataKey);
}

function getSessionDataKey(req) {
  const encoded = req.session && req.session.dataKey;
  if (!encoded) return null;
  try {
    const parsed = b64Decode(encoded);
    return parsed.length === DATA_KEY_LENGTH ? parsed : null;
  } catch {
    return null;
  }
}

function setAuthenticatedSession(req, dataKey) {
  req.session.authenticated = true;
  req.session.dataKey = b64Encode(dataKey);
}

function clearSessionAuth(req) {
  if (!req.session) return;
  delete req.session.authenticated;
  delete req.session.dataKey;
}

function getAuthConfig() {
  return getAuthConfigStmt.get() || null;
}

function getClientIp(req) {
  return String(req.ip || req.socket?.remoteAddress || "unknown");
}

function getLoginAttemptEntry(ip, now) {
  const entry = loginAttemptState.get(ip) || {
    windowStart: now,
    attemptsInWindow: 0,
    failedAttempts: 0,
    lockUntil: 0,
    lastSeenAt: now
  };

  if (now - entry.windowStart >= LOGIN_RATE_LIMIT_WINDOW_MS) {
    entry.windowStart = now;
    entry.attemptsInWindow = 0;
  }

  entry.lastSeenAt = now;
  loginAttemptState.set(ip, entry);
  return entry;
}

function checkLoginAllowed(req) {
  const now = Date.now();
  const ip = getClientIp(req);
  const entry = getLoginAttemptEntry(ip, now);

  if (entry.lockUntil > now) {
    return {
      allowed: false,
      retryAfterSeconds: Math.max(1, Math.ceil((entry.lockUntil - now) / 1000)),
      error: "Too many failed login attempts. Try again later."
    };
  }

  if (entry.attemptsInWindow >= LOGIN_RATE_LIMIT_MAX) {
    const retryAfter = entry.windowStart + LOGIN_RATE_LIMIT_WINDOW_MS - now;
    return {
      allowed: false,
      retryAfterSeconds: Math.max(1, Math.ceil(retryAfter / 1000)),
      error: "Too many login attempts. Try again later."
    };
  }

  entry.attemptsInWindow += 1;
  loginAttemptState.set(ip, entry);
  return { allowed: true };
}

function recordFailedLogin(req) {
  const now = Date.now();
  const ip = getClientIp(req);
  const entry = getLoginAttemptEntry(ip, now);
  entry.failedAttempts += 1;

  if (entry.failedAttempts >= LOGIN_LOCKOUT_THRESHOLD) {
    entry.lockUntil = now + LOGIN_LOCKOUT_MS;
    entry.failedAttempts = 0;
  }

  loginAttemptState.set(ip, entry);
}

function recordSuccessfulLogin(req) {
  const now = Date.now();
  const ip = getClientIp(req);
  const entry = getLoginAttemptEntry(ip, now);
  entry.failedAttempts = 0;
  entry.lockUntil = 0;
  loginAttemptState.set(ip, entry);
}

function cleanStaleLoginAttempts() {
  const now = Date.now();
  const maxStateAge = Math.max(LOGIN_RATE_LIMIT_WINDOW_MS, LOGIN_LOCKOUT_MS) * 2;

  for (const [ip, entry] of loginAttemptState.entries()) {
    if (entry.lastSeenAt + maxStateAge < now && entry.lockUntil < now) {
      loginAttemptState.delete(ip);
    }
  }
}

setInterval(cleanStaleLoginAttempts, 10 * 60 * 1000).unref();

function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) {
    const dataKey = getSessionDataKey(req);
    if (dataKey) {
      req.dataKey = dataKey;
      return next();
    }
  }
  return res.status(401).json({ error: "Unauthorized" });
}

function normalizeTags(tagsRaw) {
  if (!tagsRaw) return "";
  const unique = Array.from(
    new Set(
      String(tagsRaw)
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean)
    )
  );
  return unique.join(", ");
}

function extractTitle(html) {
  const $ = cheerio.load(html);
  const title = $("title").first().text().trim();
  if (title) return title;
  const ogTitle = $('meta[property="og:title"]').attr("content") || "";
  return ogTitle.trim();
}

function resolveFavicon($, sourceUrl) {
  const relIcon =
    $('link[rel="icon"]').attr("href") ||
    $('link[rel="shortcut icon"]').attr("href") ||
    $('link[rel="apple-touch-icon"]').attr("href");

  if (relIcon) {
    try {
      return new URL(relIcon, sourceUrl).toString();
    } catch {
      // Ignore invalid icon URL.
    }
  }

  try {
    const parsed = new URL(sourceUrl);
    return `${parsed.origin}/favicon.ico`;
  } catch {
    return "";
  }
}

function isPrivateIPv4(address) {
  const parts = address.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return true;
  }

  const [a, b, c] = parts;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 192 && b === 0 && c === 0) return true;
  if (a === 192 && b === 0 && c === 2) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a === 198 && b === 51 && c === 100) return true;
  if (a === 203 && b === 0 && c === 113) return true;
  if (a >= 224) return true;
  return false;
}

function isPrivateIPv6(address) {
  const normalized = String(address).toLowerCase().split("%")[0];
  if (normalized === "::" || normalized === "::1") return true;
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
  if (normalized.startsWith("fe80:")) return true;
  if (normalized.startsWith("ff")) return true;
  if (normalized.startsWith("2001:db8:")) return true;

  if (normalized.startsWith("::ffff:")) {
    const mapped = normalized.slice(7);
    if (net.isIP(mapped) === 4) {
      return isPrivateIPv4(mapped);
    }
  }

  return false;
}

function isPrivateAddress(address) {
  const ipVersion = net.isIP(address);
  if (ipVersion === 4) return isPrivateIPv4(address);
  if (ipVersion === 6) return isPrivateIPv6(address);
  return true;
}

async function assertPublicHost(hostname) {
  if (!FETCH_BLOCK_PRIVATE_IPS) return;

  const normalizedHost = String(hostname || "").trim().toLowerCase();
  if (!normalizedHost) {
    throw new Error("Could not fetch URL (invalid host)");
  }

  if (normalizedHost === "localhost" || normalizedHost.endsWith(".localhost")) {
    throw new Error("Private network hosts are blocked");
  }

  if (net.isIP(normalizedHost)) {
    if (isPrivateAddress(normalizedHost)) {
      throw new Error("Private network hosts are blocked");
    }
    return;
  }

  let resolved;
  try {
    resolved = await dns.lookup(normalizedHost, { all: true, verbatim: true });
  } catch {
    throw new Error("Could not resolve host");
  }

  if (!resolved.length) {
    throw new Error("Could not resolve host");
  }

  if (resolved.some((entry) => isPrivateAddress(entry.address))) {
    throw new Error("Private network hosts are blocked");
  }
}

async function fetchWithSafety(initialUrl) {
  let currentUrl = new URL(initialUrl);

  for (let redirectCount = 0; redirectCount <= 5; redirectCount += 1) {
    await assertPublicHost(currentUrl.hostname);

    const abortController = new AbortController();
    const timeout = setTimeout(() => abortController.abort(), FETCH_TIMEOUT_MS);
    let response;

    try {
      response = await fetch(currentUrl.toString(), {
        redirect: "manual",
        signal: abortController.signal,
        headers: {
          "User-Agent": "BookmarkerBot/1.0"
        }
      });
    } catch (error) {
      if (error && error.name === "AbortError") {
        throw new Error(`Could not fetch URL (timeout after ${FETCH_TIMEOUT_MS}ms)`);
      }
      throw new Error("Could not fetch URL");
    } finally {
      clearTimeout(timeout);
    }

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      if (!location) {
        throw new Error("Could not fetch URL (invalid redirect)");
      }

      let nextUrl;
      try {
        nextUrl = new URL(location, currentUrl);
      } catch {
        throw new Error("Could not fetch URL (invalid redirect)");
      }

      if (nextUrl.protocol !== "http:" && nextUrl.protocol !== "https:") {
        throw new Error("Only http/https URLs are supported");
      }

      currentUrl = nextUrl;
      continue;
    }

    return { response, finalUrl: currentUrl.toString() };
  }

  throw new Error("Could not fetch URL (too many redirects)");
}

async function fetchBookmarkMetadata(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error("Invalid URL");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only http/https URLs are supported");
  }

  const { response, finalUrl } = await fetchWithSafety(parsed.toString());

  if (!response.ok) {
    throw new Error(`Could not fetch URL (${response.status})`);
  }

  const html = await response.text();
  const $ = cheerio.load(html);

  let title = extractTitle(html);
  if (!title) {
    title = parsed.hostname;
  }

  const finalResolvedUrl = finalUrl || parsed.toString();
  const favicon = resolveFavicon($, finalResolvedUrl);

  return {
    url: finalResolvedUrl,
    title,
    favicon
  };
}

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

if (TRUST_PROXY) {
  const normalizedTrustProxy = String(TRUST_PROXY).trim().toLowerCase();
  if (normalizedTrustProxy === "true") {
    app.set("trust proxy", true);
  } else if (normalizedTrustProxy === "false") {
    app.set("trust proxy", false);
  } else if (/^\d+$/.test(normalizedTrustProxy)) {
    app.set("trust proxy", Number(normalizedTrustProxy));
  } else {
    app.set("trust proxy", TRUST_PROXY);
  }
} else if (IS_PRODUCTION) {
  app.set("trust proxy", 1);
}

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: COOKIE_SAMESITE,
      secure: SESSION_COOKIE_SECURE,
      maxAge: SESSION_MAX_AGE_MS
    }
  })
);

app.post("/api/setup", (req, res) => {
  if (getAuthConfig()) {
    return res.status(409).json({ error: "Password is already configured" });
  }

  const password = String(req.body.password || "");
  if (password.length < PASSWORD_MIN_LENGTH) {
    return res.status(400).json({ error: `Password must be at least ${PASSWORD_MIN_LENGTH} characters` });
  }

  const record = createPasswordRecord(password);
  const now = new Date().toISOString();

  try {
    insertAuthConfigStmt.run({
      ...record,
      createdAt: now,
      updatedAt: now
    });
  } catch {
    return res.status(500).json({ error: "Could not save password" });
  }

  const dataKey = deriveDataKey(password, record.encryptionSalt);
  const migrated = migratePlaintextData(dataKey);
  setAuthenticatedSession(req, dataKey);
  return res.status(201).json({ ok: true, migrated });
});

app.post("/api/login", (req, res) => {
  const allowed = checkLoginAllowed(req);
  if (!allowed.allowed) {
    res.set("Retry-After", String(allowed.retryAfterSeconds));
    return res.status(429).json({ error: allowed.error });
  }

  const authConfig = getAuthConfig();
  if (!authConfig) {
    return res.status(409).json({ error: "Setup required" });
  }

  const password = String(req.body.password || "");
  if (!verifyPassword(password, authConfig)) {
    recordFailedLogin(req);
    return res.status(401).json({ error: "Invalid password" });
  }

  recordSuccessfulLogin(req);
  const dataKey = deriveDataKey(password, authConfig.encryptionSalt);
  const migrated = migratePlaintextData(dataKey);
  setAuthenticatedSession(req, dataKey);
  return res.json({ ok: true, migrated });
});

app.post("/api/logout", (req, res) => {
  clearSessionAuth(req);
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.get("/api/session", (req, res) => {
  const setupRequired = !getAuthConfig();
  const dataKey = getSessionDataKey(req);
  const authenticated = Boolean(req.session && req.session.authenticated && dataKey);
  res.json({ authenticated, setupRequired });
});

app.get("/api/lists", requireAuth, (req, res) => {
  try {
    const lists = listListsStmt.all().map((row) => decryptListRow(row, req.dataKey));
    return res.json({ lists });
  } catch {
    return res.status(500).json({ error: "Could not decrypt lists" });
  }
});

app.post("/api/lists", requireAuth, (req, res) => {
  const name = String(req.body.name || "").trim();
  if (!name) {
    return res.status(400).json({ error: "List name is required" });
  }

  if (name.length > 80) {
    return res.status(400).json({ error: "List name is too long" });
  }

  try {
    const existingLists = listListsStmt.all().map((row) => decryptListRow(row, req.dataKey));
    if (existingLists.some((list) => list.name.toLowerCase() === name.toLowerCase())) {
      return res.status(409).json({ error: "List already exists" });
    }

    const maxPos = getMaxListPositionStmt.get().maxPos;
    const result = insertListStmt.run(encryptText(name, req.dataKey), maxPos + 1);
    const list = decryptListRow(getListStmt.get(result.lastInsertRowid), req.dataKey);
    return res.status(201).json({ list });
  } catch (error) {
    if (String(error.message).includes("UNIQUE")) {
      return res.status(409).json({ error: "List already exists" });
    }
    return res.status(500).json({ error: "Could not create list" });
  }
});

app.get("/api/bookmarks", requireAuth, (req, res) => {
  const tagFilter = String(req.query.tag || "").trim().toLowerCase();
  const listIdFilter = Number(req.query.listId || 0);
  const favoritesOnly = String(req.query.favorites || "") === "1";

  let items;
  try {
    items = listBookmarksStmt.all().map((row) => decryptBookmarkRow(row, req.dataKey));
  } catch {
    return res.status(500).json({ error: "Could not decrypt bookmarks" });
  }

  if (favoritesOnly) {
    items = items.filter((b) => Boolean(b.isFavorite));
  }

  if (listIdFilter) {
    items = items.filter((b) => b.listId === listIdFilter);
  }

  if (tagFilter) {
    items = items.filter((b) =>
      String(b.tags)
        .split(",")
        .map((t) => t.trim().toLowerCase())
        .includes(tagFilter)
    );
  }

  return res.json({ bookmarks: items });
});

app.post("/api/bookmarks", requireAuth, async (req, res) => {
  const { url, tags, listId: rawListId } = req.body;
  if (!url) {
    return res.status(400).json({ error: "URL is required" });
  }

  const requestedListId = Number(rawListId || defaultListId);
  const list = getListStmt.get(requestedListId);
  if (!list) {
    return res.status(400).json({ error: "Invalid list" });
  }

  try {
    const metadata = await fetchBookmarkMetadata(url);
    const max = getMaxPositionByListStmt.get(requestedListId).maxPos;

    const bookmark = {
      url: encryptText(metadata.url, req.dataKey),
      title: encryptText(metadata.title, req.dataKey),
      favicon: encryptText(metadata.favicon, req.dataKey),
      tags: encryptText(normalizeTags(tags), req.dataKey),
      isFavorite: 0,
      position: max + 1,
      createdAt: encryptText(new Date().toISOString(), req.dataKey),
      listId: requestedListId
    };

    const result = insertBookmarkStmt.run(bookmark);
    const inserted = decryptBookmarkRow(getBookmarkStmt.get(result.lastInsertRowid), req.dataKey);
    return res.status(201).json({ bookmark: inserted });
  } catch (error) {
    return res.status(400).json({ error: error.message || "Failed to add bookmark" });
  }
});

app.patch("/api/bookmarks/:id/favorite", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const existing = getBookmarkStmt.get(id);
  if (!existing) {
    return res.status(404).json({ error: "Bookmark not found" });
  }

  const nextVal = existing.isFavorite ? 0 : 1;
  updateFavoriteStmt.run(nextVal, id);
  const updated = decryptBookmarkRow(getBookmarkStmt.get(id), req.dataKey);
  return res.json({ bookmark: updated });
});

app.patch("/api/bookmarks/:id/tags", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const existing = getBookmarkStmt.get(id);
  if (!existing) {
    return res.status(404).json({ error: "Bookmark not found" });
  }

  const tags = normalizeTags(req.body.tags);
  updateTagsStmt.run(encryptText(tags, req.dataKey), id);
  const updated = decryptBookmarkRow(getBookmarkStmt.get(id), req.dataKey);
  return res.json({ bookmark: updated });
});

app.patch("/api/bookmarks/:id/list", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const listId = Number(req.body.listId || 0);
  const existing = getBookmarkStmt.get(id);
  if (!existing) {
    return res.status(404).json({ error: "Bookmark not found" });
  }

  const targetList = getListStmt.get(listId);
  if (!targetList) {
    return res.status(400).json({ error: "Invalid list" });
  }

  if (existing.listId === listId) {
    return res.json({ bookmark: decryptBookmarkRow(existing, req.dataKey), unchanged: true });
  }

  const txn = db.transaction(() => {
    shiftDownStmt.run(existing.listId, existing.position);
    const nextPos = getMaxPositionByListStmt.get(listId).maxPos + 1;
    updateBookmarkListStmt.run(listId, nextPos, id);
  });

  txn();
  const updated = decryptBookmarkRow(getBookmarkStmt.get(id), req.dataKey);
  return res.json({ bookmark: updated });
});

app.patch("/api/bookmarks/:id/move", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const direction = String(req.body.direction || "").toLowerCase();
  const existing = getBookmarkStmt.get(id);

  if (!existing) {
    return res.status(404).json({ error: "Bookmark not found" });
  }

  if (direction !== "up" && direction !== "down") {
    return res.status(400).json({ error: "Direction must be up or down" });
  }

  const siblings = listBookmarksByListStmt.all(existing.listId);
  const index = siblings.findIndex((b) => b.id === id);
  if (index === -1) {
    return res.status(404).json({ error: "Bookmark not found" });
  }

  const targetIndex = direction === "up" ? index - 1 : index + 1;
  if (targetIndex < 0 || targetIndex >= siblings.length) {
    return res.json({ bookmark: decryptBookmarkRow(existing, req.dataKey), unchanged: true });
  }

  const target = siblings[targetIndex];

  const txn = db.transaction(() => {
    updateBookmarkPositionStmt.run(target.position, id);
    updateBookmarkPositionStmt.run(existing.position, target.id);
  });

  txn();
  const updated = decryptBookmarkRow(getBookmarkStmt.get(id), req.dataKey);
  return res.json({ bookmark: updated });
});

app.delete("/api/bookmarks/:id", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const existing = getBookmarkStmt.get(id);
  if (!existing) {
    return res.status(404).json({ error: "Bookmark not found" });
  }

  const txn = db.transaction(() => {
    deleteBookmarkStmt.run(id);
    shiftDownStmt.run(existing.listId, existing.position);
  });

  txn();
  return res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, "public")));

app.listen(PORT, HOST, () => {
  console.log(`Bookmarker running on ${HOST}:${PORT}`);
});
