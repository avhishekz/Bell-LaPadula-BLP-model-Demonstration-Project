# Bell-LaPadula Security Model — Full Stack Application

A complete, working implementation of the **Bell-LaPadula mandatory access control model** with:
- **Python/Flask** backend
- **SQLite** database with bcrypt-hashed passwords
- Professional frontend (Inter font, clean layout)
- Full BLP enforcement (No Read Up, No Write Down)

---

## Quick Start

### macOS / Linux
```bash
chmod +x run.sh
./run.sh
```

### Windows
```
run.bat
```

Then open **http://localhost:5000** in your browser.

---

## Architecture

```
blp_app/
├── app.py              ← Flask backend + BLP enforcement
├── requirements.txt    ← Python dependencies
├── run.sh / run.bat    ← One-click setup & launch
├── database/
│   ├── schema.sql      ← SQLite schema (tables + seed data)
│   └── blp.db          ← Auto-created on first run
└── templates/
    └── index.html      ← Full frontend (HTML/CSS/JS)
```

---

## Database Schema

| Table | Purpose |
|---|---|
| `users` | Credentials (bcrypt hash), clearance level, role, status |
| `classification_levels` | Levels 1–4 with names and colors |
| `files` | Documents with classification level |
| `messages` | Secure chat (level-filtered) |
| `audit_log` | Every access attempt (allowed + denied) |
| `sessions` | Server-side session tokens |

---

## BLP Rules Enforced

| Rule | Property | Description |
|---|---|---|
| **No Read Up** | Simple Security | User level must be ≥ file level to read |
| **No Write Down** | ★-Property | User level must be ≤ target level to write |

---

## Demo Accounts

| Username | Password | Level | Role |
|---|---|---|---|
| `admin` | `admin123` | 4 — Top Secret | Admin |
| `manager` | `pass123` | 4 — Top Secret | User |
| `employee` | `secret456` | 3 — Secret | User |
| `intern` | `conf123` | 2 — Confidential | User |
| `public` | `open789` | 1 — Public | User |

---

## API Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/login` | Login |
| POST | `/api/auth/logout` | Logout |
| POST | `/api/auth/register` | Register (pending approval) |
| GET | `/api/files` | List all files + access flags |
| GET | `/api/files/:id/read` | Read file (BLP enforced) |
| POST | `/api/files/upload` | Upload file (BLP enforced) |
| GET | `/api/chat/messages` | Get messages (BLP filtered) |
| POST | `/api/chat/send` | Send message |
| GET | `/api/audit` | Audit log |
| GET | `/api/admin/users` | All users (admin only) |
| GET | `/api/admin/stats` | System stats (admin only) |
| POST | `/api/admin/users/:id/approve` | Approve pending user |
| POST | `/api/admin/users/:id/suspend` | Suspend user |
| DELETE | `/api/admin/users/:id/delete` | Delete user |

---

## Security Notes

- Passwords stored as **bcrypt hashes** (falls back to SHA-256+salt if bcrypt unavailable)
- All access decisions logged to `audit_log` with IP address
- Session managed server-side via Flask sessions
- BLP enforcement happens server-side in Python — frontend cannot bypass it
