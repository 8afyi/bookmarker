const path = require("path");
const express = require("express");
const session = require("express-session");
const Database = require("better-sqlite3");
const cheerio = require("cheerio");

const app = express();

const PORT = Number(process.env.PORT || 3000);
const APP_PASSWORD = process.env.APP_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET || "change-me";
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "bookmarks.db");

if (!APP_PASSWORD) {
  console.error("APP_PASSWORD environment variable is required.");
  process.exit(1);
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
`);

const bookmarkColumns = db.prepare("PRAGMA table_info(bookmarks)").all();
if (!bookmarkColumns.some((col) => col.name === "list_id")) {
  db.exec("ALTER TABLE bookmarks ADD COLUMN list_id INTEGER");
}

const getListByNameStmt = db.prepare("SELECT id, name, position FROM lists WHERE name = ?");
const getMaxListPositionStmt = db.prepare("SELECT COALESCE(MAX(position), 0) AS maxPos FROM lists");
const insertListStmt = db.prepare("INSERT INTO lists (name, position) VALUES (?, ?)");
const listListsStmt = db.prepare("SELECT id, name, position FROM lists ORDER BY position ASC, id ASC");

function ensureDefaultList() {
  const existing = getListByNameStmt.get("General");
  if (existing) return existing.id;
  const maxPos = getMaxListPositionStmt.get().maxPos;
  const result = insertListStmt.run("General", maxPos + 1);
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
  `SELECT id, position FROM bookmarks WHERE list_id = ? ORDER BY position ASC, id ASC`
);
const getBookmarkStmt = db.prepare(
  `SELECT b.id, b.url, b.title, b.favicon, b.tags, b.is_favorite AS isFavorite,
          b.position, b.created_at AS createdAt, b.list_id AS listId, l.name AS listName
   FROM bookmarks b
   JOIN lists l ON l.id = b.list_id
   WHERE b.id = ?`
);
const getListStmt = db.prepare("SELECT id, name, position FROM lists WHERE id = ?");
const updateFavoriteStmt = db.prepare("UPDATE bookmarks SET is_favorite = ? WHERE id = ?");
const updateTagsStmt = db.prepare("UPDATE bookmarks SET tags = ? WHERE id = ?");
const updateBookmarkPositionStmt = db.prepare("UPDATE bookmarks SET position = ? WHERE id = ?");
const updateBookmarkListStmt = db.prepare("UPDATE bookmarks SET list_id = ?, position = ? WHERE id = ?");
const deleteBookmarkStmt = db.prepare("DELETE FROM bookmarks WHERE id = ?");
const shiftDownStmt = db.prepare(
  "UPDATE bookmarks SET position = position - 1 WHERE list_id = ? AND position > ?"
);

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false
    }
  })
);

function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) {
    return next();
  }
  res.status(401).json({ error: "Unauthorized" });
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

app.post("/api/login", (req, res) => {
  const { password } = req.body;
  if (password === APP_PASSWORD) {
    req.session.authenticated = true;
    return res.json({ ok: true });
  }
  return res.status(401).json({ error: "Invalid password" });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.get("/api/session", (req, res) => {
  res.json({ authenticated: Boolean(req.session && req.session.authenticated) });
});

app.get("/api/lists", requireAuth, (req, res) => {
  res.json({ lists: listListsStmt.all() });
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
    const maxPos = getMaxListPositionStmt.get().maxPos;
    const result = insertListStmt.run(name, maxPos + 1);
    const list = getListStmt.get(result.lastInsertRowid);
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

  let items = listBookmarksStmt.all();

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

  res.json({ bookmarks: items });
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
      url: metadata.url,
      title: metadata.title,
      favicon: metadata.favicon,
      tags: normalizeTags(tags),
      isFavorite: 0,
      position: max + 1,
      createdAt: new Date().toISOString(),
      listId: requestedListId
    };

    const result = insertBookmarkStmt.run(bookmark);
    const inserted = getBookmarkStmt.get(result.lastInsertRowid);
    res.status(201).json({ bookmark: inserted });
  } catch (error) {
    res.status(400).json({ error: error.message || "Failed to add bookmark" });
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
  const updated = getBookmarkStmt.get(id);
  res.json({ bookmark: updated });
});

app.patch("/api/bookmarks/:id/tags", requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const existing = getBookmarkStmt.get(id);
  if (!existing) {
    return res.status(404).json({ error: "Bookmark not found" });
  }

  const tags = normalizeTags(req.body.tags);
  updateTagsStmt.run(tags, id);
  const updated = getBookmarkStmt.get(id);
  res.json({ bookmark: updated });
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
    return res.json({ bookmark: existing, unchanged: true });
  }

  const txn = db.transaction(() => {
    shiftDownStmt.run(existing.listId, existing.position);
    const nextPos = getMaxPositionByListStmt.get(listId).maxPos + 1;
    updateBookmarkListStmt.run(listId, nextPos, id);
  });

  txn();
  const updated = getBookmarkStmt.get(id);
  res.json({ bookmark: updated });
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
    return res.json({ bookmark: existing, unchanged: true });
  }

  const target = siblings[targetIndex];

  const txn = db.transaction(() => {
    updateBookmarkPositionStmt.run(target.position, id);
    updateBookmarkPositionStmt.run(existing.position, target.id);
  });

  txn();
  const updated = getBookmarkStmt.get(id);
  res.json({ bookmark: updated });
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
  res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, "public")));

app.listen(PORT, () => {
  console.log(`Bookmarker running on port ${PORT}`);
});
