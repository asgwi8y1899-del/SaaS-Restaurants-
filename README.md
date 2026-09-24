# DineOS - Restaurant Management SaaS

All-in-one restaurant management platform: POS, online orders, QR menus,
inventory, staff management, smart reports & settings.

**Stack:** Node.js + Express + SQLite (better-sqlite3) + Vanilla JS frontend.
No build step. One command to run.

## Quick start

```bash
npm install
npm start
```

Open http://localhost:3000

**Default login:** `admin@dineos.app` / `admin123`

## API overview

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/register | Create account (returns JWT) |
| POST | /api/login | Login (returns JWT) |
| GET/PUT | /api/settings | Workspace settings |
| GET/POST/DELETE | /api/menu | Menu items |
| GET/POST/PATCH/DELETE | /api/orders | Orders (PATCH = change status) |
| GET/POST/PATCH/DELETE | /api/inventory | Stock (PATCH = qty delta) |
| GET/POST/DELETE | /api/staff | Team members |
| GET | /api/stats | Dashboard stats |
| GET | /api/public/store/:userId | Storefront data (public) |
| POST | /api/public/order/:userId | Place online order (public) |

All data endpoints require `Authorization: Bearer <token>`.

## Project structure

```
dineos/
  server.js       # Express API + auth + SQLite
  package.json
  public/
    index.html    # Landing page
    app.html      # Full app (dashboard, POS, menu, inventory, staff, reports, settings)
```

## Deploy

### Local / VPS
```bash
npm install && npm start
```

### Render (free tier)
1. Push this repo to GitHub
2. Render -> New Web Service -> connect repo
3. Build command: `npm install`
4. Start command: `node server.js`
5. Add env var `JWT_SECRET` (random long string)

> Note: free-tier disks are ephemeral — SQLite resets on redeploy.
> For production with multiple restaurants, migrate to PostgreSQL
> (the SQL in server.js is compatible) and move JWT_SECRET to env.

## Customer storefront

Each restaurant gets a public online-ordering page:

    http://localhost:3000/store.html?u=<userId>

Customers browse the menu, add to cart and checkout — orders appear
in the owner's dashboard as type **Online** with the customer name.
Toggle "online" off in Settings to pause ordering.

## Multi-tenant SQL

Every data table has a `user_id` column; all queries are filtered by
the logged-in user, so each restaurant only sees its own data.
New registrations get starter data automatically.

## Security notes
- Change `admin123` immediately after first login
- Always set `JWT_SECRET` in production
- Add rate limiting + HTTPS before real launch
