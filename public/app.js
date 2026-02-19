const loginView = document.getElementById("loginView");
const appView = document.getElementById("appView");
const loginForm = document.getElementById("loginForm");
const bookmarkForm = document.getElementById("bookmarkForm");
const listForm = document.getElementById("listForm");
const loginError = document.getElementById("loginError");
const bookmarkError = document.getElementById("bookmarkError");
const listError = document.getElementById("listError");
const tagFilter = document.getElementById("tagFilter");
const sortMode = document.getElementById("sortMode");
const favoritesOnly = document.getElementById("favoritesOnly");
const logoutBtn = document.getElementById("logoutBtn");
const listsGrid = document.getElementById("listsGrid");
const listSelect = document.getElementById("listSelect");

let bookmarks = [];
let lists = [];

function formatDate(iso) {
  const date = new Date(iso);
  return date.toLocaleString();
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function hashString(value) {
  let hash = 0;
  for (let i = 0; i < value.length; i += 1) {
    hash = value.charCodeAt(i) + ((hash << 5) - hash);
    hash |= 0;
  }
  return Math.abs(hash);
}

function tagColor(tag) {
  const hue = hashString(tag) % 360;
  return {
    bg: `hsl(${hue}, 75%, 90%)`,
    border: `hsl(${hue}, 55%, 70%)`,
    text: `hsl(${hue}, 40%, 28%)`
  };
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: {
      "Content-Type": "application/json"
    },
    ...options
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || "Request failed");
  }
  return data;
}

function parseTags(tagString) {
  return (tagString || "")
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
}

function renderListSelect() {
  listSelect.innerHTML = lists
    .map((list) => `<option value="${list.id}">${escapeHtml(list.name)}</option>`)
    .join("");
}

function filteredBookmarks() {
  const tagValue = tagFilter.value.trim().toLowerCase();
  const favOnly = favoritesOnly.checked;

  let visible = bookmarks;

  if (favOnly) {
    visible = visible.filter((b) => Boolean(b.isFavorite));
  }

  if (tagValue) {
    visible = visible.filter((b) =>
      parseTags(b.tags)
        .map((tag) => tag.toLowerCase())
        .includes(tagValue)
    );
  }

  return visible;
}

function sortBookmarks(items) {
  if (sortMode.value !== "tag") {
    return [...items].sort((a, b) => a.position - b.position || a.id - b.id);
  }

  return [...items].sort((a, b) => {
    const ta = (parseTags(a.tags)[0] || "~").toLowerCase();
    const tb = (parseTags(b.tags)[0] || "~").toLowerCase();
    return ta.localeCompare(tb) || a.position - b.position || a.id - b.id;
  });
}

function renderBookmarks() {
  const visible = filteredBookmarks();
  listsGrid.innerHTML = "";

  if (!lists.length) {
    listsGrid.innerHTML = '<div class="card empty-note">No lists yet.</div>';
    return;
  }

  lists.forEach((list) => {
    const card = document.createElement("article");
    card.className = "list-card";

    const listItems = sortBookmarks(visible.filter((b) => b.listId === list.id));

    const listHtml = listItems
      .map((bookmark, index) => {
        const tags = parseTags(bookmark.tags)
          .map((tag) => {
            const colors = tagColor(tag.toLowerCase());
            return `<span class="tag-chip" style="background:${colors.bg};border-color:${colors.border};color:${colors.text}">${escapeHtml(tag)}</span>`;
          })
          .join("");

        const icon = bookmark.favicon
          ? `<img src="${escapeHtml(bookmark.favicon)}" alt="" class="bookmark-icon" loading="lazy" />`
          : '<div class="bookmark-icon"></div>';

        return `
          <li class="bookmark-item">
            ${icon}
            <div class="bookmark-main">
              <a href="${escapeHtml(bookmark.url)}" target="_blank" rel="noreferrer">${escapeHtml(bookmark.title)}</a>
              <div class="bookmark-meta">${escapeHtml(bookmark.url)}</div>
              <div class="bookmark-meta">Added: ${formatDate(bookmark.createdAt)}</div>
              <div class="tag-row">${tags || '<span class="bookmark-meta">No tags</span>'}</div>
              <div class="bookmark-actions">
                <button class="favorite ${bookmark.isFavorite ? "active" : ""}" data-action="favorite" data-id="${bookmark.id}">${bookmark.isFavorite ? "Unfavorite" : "Favorite"}</button>
                <button data-action="tags" data-id="${bookmark.id}">Edit Tags</button>
                <button data-action="move-list" data-id="${bookmark.id}">Move List</button>
                <button data-action="up" data-id="${bookmark.id}" ${sortMode.value === "tag" || index === 0 ? "disabled" : ""}>Up</button>
                <button data-action="down" data-id="${bookmark.id}" ${sortMode.value === "tag" || index === listItems.length - 1 ? "disabled" : ""}>Down</button>
                <button data-action="delete" data-id="${bookmark.id}">Delete</button>
              </div>
            </div>
          </li>
        `;
      })
      .join("");

    card.innerHTML = `
      <header class="list-header">
        <h3>${escapeHtml(list.name)}</h3>
        <small>${listItems.length} items</small>
      </header>
      <ul class="bookmark-list">
        ${listItems.length ? listHtml : '<li class="empty-note">No bookmarks in this list.</li>'}
      </ul>
    `;

    listsGrid.appendChild(card);
  });
}

async function refreshData() {
  const [bookmarkData, listData] = await Promise.all([api("/api/bookmarks"), api("/api/lists")]);
  bookmarks = bookmarkData.bookmarks;
  lists = listData.lists;
  renderListSelect();
  renderBookmarks();
}

async function checkSession() {
  const result = await api("/api/session");
  if (!result.authenticated) return;

  loginView.classList.add("hidden");
  appView.classList.remove("hidden");
  await refreshData();
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  loginError.textContent = "";

  const password = document.getElementById("password").value;

  try {
    await api("/api/login", {
      method: "POST",
      body: JSON.stringify({ password })
    });
    loginForm.reset();
    loginView.classList.add("hidden");
    appView.classList.remove("hidden");
    await refreshData();
  } catch (error) {
    loginError.textContent = error.message;
  }
});

bookmarkForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  bookmarkError.textContent = "";

  const url = document.getElementById("url").value;
  const tags = document.getElementById("tags").value;
  const listId = Number(listSelect.value || 0);

  try {
    await api("/api/bookmarks", {
      method: "POST",
      body: JSON.stringify({ url, tags, listId })
    });
    bookmarkForm.reset();
    await refreshData();
  } catch (error) {
    bookmarkError.textContent = error.message;
  }
});

listForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  listError.textContent = "";

  const name = document.getElementById("listName").value.trim();
  if (!name) return;

  try {
    await api("/api/lists", {
      method: "POST",
      body: JSON.stringify({ name })
    });
    listForm.reset();
    await refreshData();
  } catch (error) {
    listError.textContent = error.message;
  }
});

listsGrid.addEventListener("click", async (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;

  const action = target.dataset.action;
  const id = Number(target.dataset.id);
  if (!action || !id) return;

  bookmarkError.textContent = "";

  try {
    if (action === "favorite") {
      await api(`/api/bookmarks/${id}/favorite`, { method: "PATCH" });
    }

    if (action === "tags") {
      const current = bookmarks.find((b) => b.id === id);
      const next = prompt("Comma-separated tags:", current?.tags || "");
      if (next === null) return;
      await api(`/api/bookmarks/${id}/tags`, {
        method: "PATCH",
        body: JSON.stringify({ tags: next })
      });
    }

    if (action === "move-list") {
      const current = bookmarks.find((b) => b.id === id);
      const choices = lists.map((list) => `${list.id}:${list.name}`).join(", ");
      const next = prompt(`Move to list id (${choices}):`, String(current?.listId || ""));
      if (next === null) return;
      const listId = Number(next.trim());
      if (!Number.isInteger(listId) || !listId) {
        throw new Error("Invalid list id");
      }
      await api(`/api/bookmarks/${id}/list`, {
        method: "PATCH",
        body: JSON.stringify({ listId })
      });
    }

    if (action === "up" || action === "down") {
      await api(`/api/bookmarks/${id}/move`, {
        method: "PATCH",
        body: JSON.stringify({ direction: action })
      });
    }

    if (action === "delete") {
      const ok = confirm("Delete this bookmark?");
      if (!ok) return;
      await api(`/api/bookmarks/${id}`, { method: "DELETE" });
    }

    await refreshData();
  } catch (error) {
    bookmarkError.textContent = error.message;
  }
});

tagFilter.addEventListener("input", renderBookmarks);
favoritesOnly.addEventListener("change", renderBookmarks);
sortMode.addEventListener("change", renderBookmarks);

logoutBtn.addEventListener("click", async () => {
  await api("/api/logout", { method: "POST" });
  appView.classList.add("hidden");
  loginView.classList.remove("hidden");
  bookmarks = [];
  lists = [];
  renderBookmarks();
});

checkSession().catch(() => {
  // Not logged in.
});
