# PHP-LoginSystem

A production-ready PHP authentication system with two-factor authentication, AI-powered security features, session management, and full audit logging.

---

## Features

### Core Authentication
- **Registration** with email/password, bcrypt hashing (`password_hash()`/`password_verify()`)
- **Login** with brute-force lockout (5 failures / 15 minutes)
- **Remember Me** persistent cookie (30-day token, hashed SHA-256 in DB)
- **Logout** — properly invalidates session and clears remember-me cookie/token

### Email Verification
- New accounts require email verification before first login
- 24-hour single-use token sent via `mail()` (demo link shown inline in dev mode)
- Resend verification link from profile or login page

### Two-Factor Authentication (2FA)
- RFC 6238 TOTP — compatible with Google Authenticator, Authy, etc.
- QR code setup via `totp_setup.php`
- 10 one-time backup codes (SHA-256 hashed) for account recovery
- Separate `backup_codes.php` management page

### Password Security
- **Breach check** — k-anonymity HIBP API (Have I Been Pwned) on registration and password change
- **Password history** — prevents reuse of last N passwords
- **Password reset** flow with 1-hour token, delivered via email

### Session & Access Management
- **Session manager** — view and revoke all active remember-me sessions
- **IP blocklist** — admin-managed ban list; blocked IPs cannot log in or restore sessions via cookie
- **Account status** — `active` / `pending` / `rejected`; non-active accounts cannot log in
- **New-IP alerts** — in-app notification and audit event when login comes from an unrecognised IP

### Magic Links
- Passwordless login via emailed one-time link (24-hour expiry, single-use)

### Notifications
- Real-time in-app notification bell on dashboard (polling `get_notifications.php`)
- Types: `info`, `warning`, `danger`, `success`

### Admin Panel (`admin.php`)
- User management: list, status toggle, role assignment
- IP blocklist management
- Visible only to accounts with `is_admin = 1`

### AI Features (requires Anthropic API key)
| Page | Feature |
|------|---------|
| `security_report.php` | Full AI security analysis of account activity |
| `ai_password.php` | Password strength analyser |
| `ai_passgen.php` | Secure password generator |
| `ai_username.php` | Username suggester |
| `ai_tip.php` | Daily security tip |
| `ai_chat.php` | Security assistant chatbot |
| `ai_threat.php` | Threat assessment from login history |
| `ai_anomaly.php` | Anomaly detection in account activity |
| `ai_phishing.php` / `phishing.php` | Phishing email analyser |
| `ai_quiz.php` | Security awareness quiz |
| `ai_faq.php` | AI-powered FAQ |
| `ai_recovery.php` | Account recovery assistant |
| `ai_password_audit.php` | Bulk password hygiene audit |
| `ai_security_score.php` | Security score with recommendations |
| `ai_login_help.php` | Login troubleshooting assistant |
| `ai_email.php` | AI email composition helper |

### Audit & Compliance
- **Audit log** (`tbl_audit_log`) — every security event logged with IP and timestamp
- **Login history** with IP geolocation lookup (`get_geo.php`)
- **CSV export** of login history (`export_log.php`)
- **GDPR data export** (`data_export.php`) — full JSON download of all personal data (passwords excluded)
- **Account deletion** (`delete_account.php`)

### Onboarding
- Security setup checklist (`onboarding.php`) guides new users through enabling 2FA, verifying email, etc.

---

## Bug Fixes (this release)

| # | File | Bug | Fix |
|---|------|-----|-----|
| 1 | `logout.php` | Remember-me cookie was never cleared on logout, allowing immediate re-login | Cookie deleted from browser and matching token deleted from `tbl_remember_tokens` |
| 2 | `session_manager.php` | "This session" badge never appeared because `token_hash` was not fetched | Added `token_hash` to SELECT; current-session detection now works |
| 3 | `change_password.php` | Used raw `session_start()` check instead of `auth_check.php`, so remember-me users were rejected | Replaced with `require_once 'auth_check.php'` |
| 4 | `system.sql` | Only contained bare two-column `tbl_signup` (MyISAM/latin1); fresh installs were non-functional | Fully rewritten with all 12 tables, InnoDB, utf8mb4 |
| 5 | `homepage.php` | `position:fixed` declared twice in `#notif-bell` CSS block | Removed duplicate declaration |
| 6 | `config.php` | No DB connection error check; `$_POST` accessed without null coalescing | Added `!$con` exit guard; switched to `?? ''` |
| 7 | `admin.php` | `$msg` output without `htmlspecialchars()`, creating potential XSS | Added `htmlspecialchars()` at output point |

---

## New Features (this release)

### 1. Email Verification
Users must verify their email before they can log in. On registration, a 24-hour token is generated and stored (SHA-256 hashed) in `tbl_email_verifications`. If the system cannot send email, the verification link is displayed inline (demo mode).

Related files: `verify_email.php`, `resend_verification.php`, changes to `config.php`, `validation.php`, `login.php`, `profile.php`

### 2. Registration Rate Limiting
Prevents abuse by limiting signups to 5 per IP address per hour. Uses the existing `tbl_audit_log` (event = `'registration'`) — no additional table required.

Related files: `config.php`

### 3. GDPR Data Export
Users can download all their personal data as a JSON file from their profile page. The export includes: account metadata, full login history, failed attempts, audit log, notifications, active sessions, and backup code counts. Passwords are explicitly excluded.

Related files: `data_export.php`, `profile.php`

---

## Requirements

- PHP 7.2+
- MySQL 5.7+ / MariaDB 10.3+
- A web server (Apache, Nginx, or PHP built-in for development)
- (Optional) An MTA/sendmail for email delivery
- (Optional) Anthropic API key for AI features

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Ron-Web-Dotcom/PHP-LoginSystem.git
cd PHP-LoginSystem
```

### 2. Import the database schema

```bash
mysql -u root -p < loginsystem/system.sql
```

This creates the `system` database with all 12 tables.

### 3. Configure the Anthropic API key (optional)

Edit `loginsystem/api_config.php` and replace the placeholder:

```php
define('ANTHROPIC_API_KEY', 'YOUR_API_KEY_HERE');
```

Get a key at https://console.anthropic.com

### 4. Serve the application

**Development (PHP built-in server):**
```bash
php -S localhost:8080 -t loginsystem/
```
Then visit http://localhost:8080/login.php

**Production (Apache):**
Point your document root to `loginsystem/` or configure a virtual host.

### 5. Create an admin account

Register normally, then run:
```sql
UPDATE system.tbl_signup SET is_admin = 1 WHERE email = 'your@email.com';
```

---

## Database Schema

| Table | Purpose |
|-------|---------|
| `tbl_signup` | User accounts (email, bcrypt password, 2FA secret, roles, flags) |
| `tbl_login_attempts` | Failed login records for lockout tracking |
| `tbl_session_log` | Successful login history (IP, timestamp) |
| `tbl_remember_tokens` | Persistent "remember me" session tokens |
| `tbl_password_resets` | Password reset tokens (1-hour expiry) |
| `tbl_ip_blocklist` | Admin-managed IP bans |
| `tbl_audit_log` | Security event history (all actions) |
| `tbl_password_history` | Previous password hashes (prevent reuse) |
| `tbl_magic_links` | Passwordless login tokens |
| `tbl_backup_codes` | 2FA backup codes (hashed) |
| `tbl_notifications` | In-app user notifications |
| `tbl_email_verifications` | Email verification tokens |

---

## File Reference

| File | Role |
|------|------|
| `login.php` | Login form (username + password, magic link option) |
| `config.php` | Registration handler |
| `validation.php` | Login authentication handler |
| `auth_check.php` | Shared auth gate (include at top of protected pages) |
| `logout.php` | Session + cookie teardown |
| `homepage.php` | Dashboard (post-login landing page) |
| `profile.php` | User profile and security overview |
| `change_password.php` | Authenticated password change |
| `forgot_password.php` | Password reset request |
| `reset_password.php` | Password reset with token |
| `totp_setup.php` | 2FA enrolment (QR code + secret) |
| `totp_verify_page.php` | 2FA code entry during login |
| `backup_codes.php` | View and regenerate 2FA backup codes |
| `magic_link.php` | Request a magic link |
| `magic_auth.php` | Magic link authentication handler |
| `verify_email.php` | Email verification landing page |
| `resend_verification.php` | Resend verification email |
| `session_manager.php` | View and revoke remember-me sessions |
| `audit_log.php` | User's personal audit log viewer |
| `security_report.php` | AI-powered security report |
| `onboarding.php` | Security setup checklist |
| `export_log.php` | CSV login history export |
| `data_export.php` | GDPR JSON data export |
| `delete_account.php` | Account self-deletion |
| `admin.php` | Admin panel (user management, IP blocklist) |
| `totp.php` | RFC 6238 TOTP library |
| `utils.php` | Shared helpers: `get_db()`, `log_audit()`, `notify()`, `is_ip_blocked()` |
| `api_config.php` | Anthropic API key + shared `call_claude()` helper |
| `check_hibp.php` | AJAX endpoint — HIBP k-anonymity breach check |
| `get_geo.php` | AJAX endpoint — IP geolocation lookup |
| `get_notifications.php` | AJAX endpoint — unread notification count |
| `mark_notifications_read.php` | AJAX endpoint — mark notifications read |
| `system.sql` | Full database schema (import once) |
| `style/cleanup.css` | Global dark glassmorphism theme |

---

## Security Notes

- All database queries use **prepared statements** (no raw string interpolation of user input).
- Tokens (remember-me, password reset, magic link, email verification) are stored as **SHA-256 hashes** only; raw tokens never touch the database.
- Passwords are hashed with **bcrypt** via `password_hash(PASSWORD_DEFAULT)`.
- TOTP secrets are stored in plaintext in the database — consider encrypting at rest in high-security deployments.
- The `mail()` function is used for sending emails. In production, replace with a proper SMTP library (PHPMailer, Symfony Mailer, etc.) and configure SPF/DKIM records.
- DB credentials are hardcoded as `root` with no password — **change these before deploying to any non-local environment**.

---

## License

MIT
