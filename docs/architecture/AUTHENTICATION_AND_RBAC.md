# Authentication & Role-Based Access Control (RBAC) Architecture

**Repository**: `seucra/vulnarability-prioritization-triage-system`  
**Phase**: `Phase WDL-2 — Authentication & Access Control Implementation`

---

## 1. Overview & Prototype Scope

The **Vulnerability Prioritization & Triage System** implements a functional, demonstration-level authentication and server-enforced Role-Based Access Control (RBAC) system for the Web Design Lab academic prototype.

> [!NOTE]
> This authentication system is designed specifically for research demonstration and triage workflow evaluation. It is not presented as an enterprise-grade Identity & Access Management (IAM) infrastructure.

---

## 2. User Data Model & Persistence

User account persistence is managed in a lightweight local SQLite database (`data/auth_users.sqlite`).

### SQLite Schema (`users` table)

```sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1
);
```

### Password Hashing Security
- **Algorithm**: `PBKDF2-HMAC-SHA256`
- **Iterations**: `100,000`
- **Salt**: 16-byte cryptographically secure random salt generated via `secrets.token_bytes(16)`
- **Format**: `pbkdf2_sha256$100000$<salt_b64>$<key_b64>`
- **Plaintext Storage**: Strictly prohibited. Plaintext passwords are never logged or stored.

---

## 3. Session Mechanism & Signed Token Engine

A JWT-compatible HMAC-SHA256 signed session token engine is implemented using 100% Python standard library (`hmac`, `hashlib`, `json`, `base64`).

### Token Structure
- **Format**: `<base64url(header)>.<base64url(payload)>.<base64url(signature)>`
- **Algorithm**: `HMAC-SHA256`
- **Payload Claims**:
  ```json
  {
    "sub": "1",
    "email": "admin@vuln-triage.sec",
    "role": "admin",
    "iat": 1786214400,
    "exp": 1786300800
  }
  ```
- **Validity Duration**: 24 Hours (`86,400` seconds)
- **Header Transmission**: Standard HTTP `Authorization: Bearer <token>` header.

---

## 4. Roles & Authorization Matrix

The application implements three explicit user roles:

| Role | Purpose | Allowed Endpoints & Workspaces | Restricted Endpoints & Workspaces |
| :--- | :--- | :--- | :--- |
| **Security Analyst** (`analyst`) | Operational vulnerability triage | Explorer (`/vulnerabilities`), Predictions (`/predict/cvss`, `/predict/kev`), Prioritization (`/prioritize`), Explainability (`/explain`), Provenance (`/provenance`) | Admin directory (`/auth/users`), User status updates |
| **Researcher** (`researcher`) | Methodology & model evaluation | Explorer, Predictions (`/predict/cvss`, `/predict/kev`), Explainability (`/explain`), Provenance (`/provenance`) | Prioritization Sandbox (`/prioritize`), Admin directory (`/auth/users`) |
| **Administrator** (`admin`) | Demonstration administration | All application workspaces + Admin directory (`/auth/users`), Account enable/disable status toggle | Cannot disable primary admin account |

---

## 5. Demonstration Administrator Provisioning

The database engine automatically seeds a default demonstration Administrator account upon initialization:

- **Email**: `admin@vuln-triage.sec`
- **Password**: `AdminDemoPassword123!`
- **Role**: `admin`
- **Privilege Escalation Protection**: Public self-registration permits selecting only `analyst` or `researcher` roles. Attempting `role="admin"` during public registration returns HTTP `400 Bad Request` / `422 Unprocessable Entity`.

---

## 6. Authentication API Endpoints

All authentication endpoints are located under `/api/v1/auth/`:

```text
POST  /api/v1/auth/register    Public registration (Security Analyst or Researcher)
POST  /api/v1/auth/login       Credential authentication & token issuance
GET   /api/v1/auth/me          Returns active user context and role
POST  /api/v1/auth/logout      Invalidates user session
GET   /api/v1/auth/users       Lists all user accounts (Admin Only - HTTP 403 for others)
PATCH /api/v1/auth/users/{id}/status  Enables or disables a user account (Admin Only)
```

---

## 7. Client Session Recovery & Route Guards

- **Session Recovery**: On application load, `app.js` inspects `localStorage` for `wdl_auth_token`. If present, `GET /api/v1/auth/me` validates the token and restores `currentUser` state.
- **Client Route Guards**:
  - Unauthenticated access to protected routes (`#dashboard`, `#explorer`, `#predict`, `#prioritize`, `#explain`, `#provenance`, `#profile`, `#admin`) renders/redirects to `#login`.
  - Attempts by `researcher` role to access `#prioritize` render an HTTP 403 Access Denied card.
  - Attempts by non-admin roles to access `#admin` render an HTTP 403 Access Denied card.
- **Backend Authority**: Client route guards serve UX purposes only. All security boundaries are strictly enforced server-side by FastAPI dependencies `get_current_user` and `require_roles(...)`.
