# Bookmarker

Single-user, password-protected bookmark manager with:
- URL paste to add bookmarks
- Auto-fetch title + favicon + date added
- Favorites + favorites-only filtering
- Color-coded tags + tag filtering/sorting
- Custom lists and side-by-side list cards (desktop-first)
- Manual ordering (up/down) within each list
- Dockerized deployment

## Run with Docker Compose

1. Create env file:
   ```bash
   cp .env.example .env
   ```
2. Edit `.env` and set secure values.
3. Build and run:
   ```bash
   docker compose up --build
   ```
4. Open `http://localhost:3000`

## Local run (without Docker)

```bash
npm install
APP_PASSWORD=your-password SESSION_SECRET=your-secret npm start
```

## Notes

- Uses SQLite (`bookmarks.db`) for persistence.
- In Docker, DB is stored in volume `bookmarks_data`.
- Default list is `General`.
- This app is intended for single-user/self-hosted usage.
