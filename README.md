# SecureVault

Zero-knowledge password manager (Epitech project).

## Structure

- `backend/` - Node/Express server
- `frontend/` - React/Vite client
- `docs/` - Documentation

## Setup

1. **Start PostgreSQL** (requires Docker & Docker Compose):
   ```bash
   docker compose up -d
   ```
   This will initialize the database with the schema defined in `backend/init/schema.sql`.

2. **Backend**:
   ```bash
   cd backend
   npm install
   npm run dev   # runs with nodemon on http://localhost:3000
   ```

3. **Frontend**:
   ```bash
   cd frontend
   npm install
   npm run dev   # runs Vite dev server on http://localhost:5173
   ```

4. **Environment Variables** (optional):
   - Create `.env` in `backend/` for PORT, PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE if needed.
   - Defaults assume the docker-compose service (host: localhost, port: 5432, user: securevault, password: securevault_pass, db: securevault).

## License

MIT
