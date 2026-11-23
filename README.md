# DB IT Consulting: Time Tracking & Invoicing

Self-hosted time tracking and invoicing for DB IT Consulting. Built security-first:
the full rules are in the project spec (`DB_Invoicing_App_Spec.md`).

## What's built so far (step 1: security foundation)

| Area | What it does |
|---|---|
| Network | Container publishes only on `127.0.0.1:8080`. Reached only through Cloudflare Tunnel + Cloudflare Access (MFA). |
| Container | Non-root user (uid 10001), read-only filesystem, all Linux capabilities dropped, no-new-privileges, log rotation (5 × 10 MB). |
| Secrets | Only in `.env` (excluded from git and the image). TOTP secret encrypted at rest (Fernet). |
| Sign-in | scrypt-hashed password (12+ chars), then mandatory TOTP (Microsoft Authenticator). 10 one-time backup codes, stored hashed. |
| Lockout | 5 failed attempts → locked 15 min, exact even under parallel requests (each attempt is reserved before it's checked). Locked and wrong-password answers look and time the same. Alert at 3 failures, on lockout, and when one IP hits 3 or 20 failures. Repeated blocked attempts are summarized in the audit log, not written one by one. |
| Sessions | Server-side; cookie is `HttpOnly`, `Secure`, `SameSite=Lax`, `__Host-` prefixed. 30-min idle / 12-h max. New token at every sign-in. |
| Re-check 2FA | Changing the password, moving the authenticator or regenerating backup codes needs a 2FA code from the last 5 minutes. |
| CSRF | Token on every form + Origin check. |
| Headers | Strict CSP, no framing, no referrer, HSTS, `no-store`. |
| Audit log | Separate database; append-only (DB triggers) and HMAC hash-chained with a signed head. Edits, removed entries, a deleted log or a restored older copy are detected (a checkpoint in the main database remembers the newest entry). A change is never kept without its audit entry (if the audit write fails, the change is rolled back). Search, filters, CSV export. Secrets are redacted before anything is written. Limit: someone with full control of the server and the .env keys could rewrite both databases; sending the signed checkpoint off-server (daily email) comes with the Microsoft 365 step. |
| Alerts | Red dashboard banner until acknowledged: new IP/device, 3+ failed sign-ins, lockout, password/2FA changes, backup-code use. (Emailing them from `billing@` comes with the Microsoft Graph step.) |
| Updates | Dependabot (pip, Docker, Actions). CI on every change + weekly: tests, pip-audit, Trivy image scan. Security Status page in the app. |

## Deploying (when the Ubuntu server is ready)

```bash
git clone https://github.com/I-love-hasham/db-invoicing.git
cd db-invoicing
python3 scripts/generate_env.py          # creates .env (chmod 600) and prints the one-time setup token
sudo install -d -o 10001 -g 10001 -m 700 data
BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ) docker compose up -d --build
```

Then point the Cloudflare Tunnel public hostname at `http://localhost:8080`, put a
Cloudflare Access policy (your email + MFA) in front of it, open the site and go to `/setup`.

**Back up `.env` offline.** Without `ENCRYPTION_KEY` the 2FA secret can't be read, and
without `AUDIT_HMAC_KEY` the audit log can't be verified.

## Setting up email from billing@ (Microsoft 365)

The app can **only send**, **only from billing@**. It never reads any mailbox.

1. **Shared mailbox:** admin.microsoft.com → Teams & groups → Shared mailboxes → add `billing@yourdomain`.
   Keep sign-in blocked; no license.
2. **App registration:** entra.microsoft.com → App registrations → New registration →
   name `DB Invoicing (send-only)`, single tenant, no redirect URI.
   **Do not add any API permissions** (not even Mail.Send) — the permission is given in Exchange
   in step 5, scoped to one mailbox. An Entra Mail.Send grant would apply to *every* mailbox.
3. **Certificate** (on the server, in the project folder):
   ```bash
   sudo install -d -o 10001 -g 10001 -m 700 secrets
   openssl req -x509 -newkey rsa:3072 -sha256 -days 730 -nodes -subj "/CN=db-invoicing" \
     -keyout /tmp/k.pem -out /tmp/c.pem
   cat /tmp/k.pem /tmp/c.pem | sudo tee secrets/m365.pem >/dev/null && shred -u /tmp/k.pem
   sudo chown 10001:10001 secrets/m365.pem && sudo chmod 600 secrets/m365.pem
   ```
   Upload **only `/tmp/c.pem`** (the public certificate) to the app registration →
   Certificates & secrets → Certificates. The private key never leaves the server.
4. **.env:** set `M365_TENANT_ID`, `M365_CLIENT_ID` (Application ID) and `M365_SENDER=billing@yourdomain`.
5. **Exchange RBAC for Applications** (Exchange Online PowerShell):
   ```powershell
   Connect-ExchangeOnline
   # IDs from Entra → Enterprise applications (NOT App registrations)
   New-ServicePrincipal -AppId <Application ID> -ObjectId <Object ID> -DisplayName "DB Invoicing (send-only)"
   New-ManagementScope -Name "DB Invoicing - billing only" -RecipientRestrictionFilter "PrimarySmtpAddress -eq 'billing@yourdomain'"
   New-ManagementRoleAssignment -Name "DB Invoicing send" -Role "Application Mail.Send" -App <Application ID> -CustomResourceScope "DB Invoicing - billing only"
   # check: InScope must be True for billing@ and False for any other mailbox
   Test-ServicePrincipalAuthorization -Identity <Application ID> -Resource billing@yourdomain
   Test-ServicePrincipalAuthorization -Identity <Application ID> -Resource you@yourdomain
   ```
   `Test-ServicePrincipalAuthorization` only checks Exchange grants, so also confirm the app
   registration's **API permissions** list in Entra is empty. RBAC changes can take a while
   (up to about an hour) to apply.
6. **SPF, DKIM, DMARC** on the domain, so invoices don't land in spam.
7. Restart the app (`docker compose up -d`), then Settings → Email → set the copy address → **Send a test email**.

**Kill switch:** disable the app registration (or remove the role assignment) — sending stops immediately.

## Updating (monthly patch day)

1. Merge the Dependabot PRs on GitHub (CI must be green).
2. On the server: `./scripts/update.sh`
3. In the app: check **Security Status** and skim the audit log.

## Running the tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```
