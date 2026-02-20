![Screen shot](bookmarker.png)

Note: this app is intended for single-user/self-hosted usage. I would not recommend putting this on the WAN without extensive testing.  

## Run

1. Create env file:
   ```bash
   cp .env.example .env
   ```
2. Edit `.env` and set a strong `SESSION_SECRET`.
3. Build and run:
   ```bash
   docker compose up --build
   ```
4. Open `http://localhost:3000`.
5. On first launch, create a master password in the setup screen.

## Environment Variables

- `SESSION_SECRET`: required, long random string used to sign session cookies.
- `NODE_ENV`: `development` or `production` (production enables secure cookies and should run behind HTTPS).
- `HOST`: bind address (use `0.0.0.0` in Docker, `127.0.0.1` for local-only host bind).
- `PORT`: HTTP port.
- `DB_PATH`: SQLite file path.
- `SESSION_MAX_AGE_MS`: session cookie lifetime in milliseconds.
- `COOKIE_SAMESITE`: `lax`, `strict`, or `none`.
- `TRUST_PROXY`: Express trust proxy setting (`1`, `true`, etc.) when behind a reverse proxy.
- `PASSWORD_MIN_LENGTH`: minimum master password length.
- `LOGIN_RATE_LIMIT_WINDOW_MS`: login rate-limit window duration.
- `LOGIN_RATE_LIMIT_MAX`: max login attempts per window per IP.
- `LOGIN_LOCKOUT_THRESHOLD`: failed login attempts before temporary lockout.
- `LOGIN_LOCKOUT_MS`: lockout duration after threshold is reached.
- `FETCH_TIMEOUT_MS`: timeout for bookmark metadata fetch requests.
- `FETCH_BLOCK_PRIVATE_IPS`: set `true` to block private/loopback hosts during metadata fetch.


