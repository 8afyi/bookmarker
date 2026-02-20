const path = require("path");
const crypto = require("crypto");
const express = require("express");
const session = require("express-session");
const Database = require("better-sqlite3");
const cheerio = require("cheerio");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET || "change-me";
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "bookmarks.db");
const IS_PRODUCTION = process.env.NODE_ENV === "production";

const PASSWORD_MIN_LENGTH = 12;
const DATA_KEY_LENGTH = 32;
const ENCRYPTED_PREFIX = "enc.v1";

if (SESSION_SECRET === "change-me") {
  console.warn("SESSION_SECRET is using the default value. Set a strong random secret.");
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

  const response = await fetch(parsed.toString(), {
    redirect: "follow",
    headers: {
      "User-Agent": "BookmarkerBot/1.0"
    }
  });

  if (!response.ok) {
    throw new Error(`Could not fetch URL (${response.status})`);
  }

  const html = await response.text();
  const $ = cheerio.load(html);

  let title = extractTitle(html);
  if (!title) {
    title = parsed.hostname;
  }

  const favicon = resolveFavicon($, response.url || parsed.toString());

  return {
    url: response.url || parsed.toString(),
    title,
    favicon
  };
}

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

if (IS_PRODUCTION) {
  app.set("trust proxy", 1);
}

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: IS_PRODUCTION,
      maxAge: 1000 * 60 * 60 * 12
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
  const authConfig = getAuthConfig();
  if (!authConfig) {
    return res.status(409).json({ error: "Setup required" });
  }

  const password = String(req.body.password || "");
  if (!verifyPassword(password, authConfig)) {
    return res.status(401).json({ error: "Invalid password" });
  }

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

app.listen(PORT, () => {
  console.log(`Bookmarker running on port ${PORT}`);
});
