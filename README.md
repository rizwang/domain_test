# Domain Health Checker

Laravel app with two domain tools that share the same bulk-processing infrastructure:

1. **Blacklist + DNS Checker** — DNSBL status + MX / SPF / DKIM / DMARC / DNS records  
2. **Mail Provider Detection** — Google Workspace / Microsoft 365 / Other / Not Detected  

Single checks run immediately in the request. Bulk CSV/TXT uploads are processed in the background (one job per domain) so results appear as each domain finishes.

---

## Requirements

- PHP **8.3+**
- Composer
- Node.js + npm (for frontend assets)
- SQLite (default) or MySQL/PostgreSQL
- No Redis required (default queue driver is **database**)

---

## Project setup

```bash
# 1. Install PHP dependencies
composer install

# 2. Environment
cp .env.example .env
php artisan key:generate

# 3. Database (SQLite is already configured by default)
touch database/database.sqlite
php artisan migrate

# 4. Frontend assets
npm install
npm run build
```

Optional: if you use MySQL instead of SQLite, update `DB_*` in `.env`, then run `php artisan migrate`.

---

## Run the application

You need **two terminals**.

**Terminal 1 — web server**

```bash
php artisan serve
```

Open:

- DNS checker: http://127.0.0.1:8000/dns-checker  
- Provider checker: http://127.0.0.1:8000/provider-checker  

**Terminal 2 — queue worker (required for bulk uploads)**

```bash
php artisan queue:work --tries=3 --timeout=120
```

Without the worker, single checks still work; bulk jobs stay in `queued` until a worker is running.

For faster bulk processing you can start a second worker in another terminal (same command). With SQLite, prefer **1–2 workers** to avoid database lock contention.

---

## Sample CSV files

Ready-made 30-row uploads:

- Task 1: [`samples/task1-dns-blacklist-30.csv`](samples/task1-dns-blacklist-30.csv)
- Task 2: [`samples/task2-provider-30.csv`](samples/task2-provider-30.csv)

---

## Features

### Task 1 — Blacklist + DNS Checker
- Single domain/email input (email → domain extracted automatically)
- Bulk CSV/TXT with live progress (`347 / 1,000 checked`)
- Status per row: Queued → Checking → Completed / Failed
- DNSBL (Spamhaus, SpamCop, Barracuda, etc.)
- MX, SPF, DKIM (when selector provided), DMARC, A/AAAA, CNAME, NS, PTR
- Filters + CSV export

### Task 2 — Mail Provider Detection
- Detects Google Workspace, Microsoft 365, Other, or Not Detected
- Uses MX first, plus SPF/TXT and autodiscover CNAME signals
- Same single/bulk/poll/filter/export UX as Task 1

---

## Queue notes

Default in `.env`:

```env
QUEUE_CONNECTION=database
```

This uses Laravel’s `jobs` table — **no Redis install needed**.

Optional: for higher bulk throughput, install Redis and set:

```env
QUEUE_CONNECTION=redis
REDIS_CLIENT=predis
```

Then run: `php artisan queue:work redis --tries=3 --timeout=120`

---

## Config

See [`config/domain_checker.php`](config/domain_checker.php) for:

- DNSBL list
- DNS timeouts / retries
- Max bulk rows / upload size
- Provider MX / SPF detection patterns
