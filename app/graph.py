"""Microsoft Graph, send-only, from ONE mailbox (billing@).

- Signs in with a certificate (no client secret): a short-lived JWT signed PS256
  with the private key, per Microsoft's "certificate credentials" spec.
- Only two hosts are ever contacted: login.microsoftonline.com and graph.microsoft.com.
- Only one Graph call is ever made: POST /users/{billing@}/sendMail.
  The Entra app has Mail.Send only, and Exchange RBAC for Applications limits it
  to the billing@ mailbox, so even a stolen key couldn't send as anyone else.
- Never logs tokens, message bodies or attachments.
"""
import base64
import json
import os
import stat
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from flask import current_app

LOGIN_HOST = "login.microsoftonline.com"
GRAPH_HOST = "graph.microsoft.com"
ALLOWED_HOSTS = {LOGIN_HOST, GRAPH_HOST}
TIMEOUT = 20
MAX_ATTACHMENT_BYTES = 3 * 1024 * 1024   # Graph's limit for a simple sendMail

_token = {"value": None, "expires": 0.0, "for": None}


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise GraphError(f"Blocked: Microsoft answered with a redirect (HTTP {code}).")


# No redirects (the token must never follow one to another host) and no proxy
# picked up from environment variables.
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirects())
_token_lock = threading.Lock()


class GraphError(Exception):
    """Safe to show and log: contains a status/code, never secrets or content."""


def configured() -> bool:
    cfg = current_app.config
    return all(cfg.get(k) for k in ("M365_TENANT_ID", "M365_CLIENT_ID", "M365_SENDER", "M365_CERT_PATH")) \
        and os.path.isfile(cfg["M365_CERT_PATH"])


def status() -> dict:
    cfg = current_app.config
    missing = [k for k in ("M365_TENANT_ID", "M365_CLIENT_ID", "M365_SENDER") if not cfg.get(k)]
    cert = cfg.get("M365_CERT_PATH") or ""
    info = {"configured": False, "sender": cfg.get("M365_SENDER") or "", "missing": missing,
            "cert_found": bool(cert) and os.path.isfile(cert), "cert_problem": None, "cert_expires": None}
    if info["cert_found"]:
        try:
            _, cert_obj = _load_credentials(cert)
            info["cert_expires"] = cert_obj.not_valid_after_utc.date().isoformat()
        except GraphError as e:
            info["cert_problem"] = str(e)
    info["configured"] = not missing and info["cert_found"] and not info["cert_problem"]
    return info


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _load_credentials(path: str):
    st = os.stat(path)
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise GraphError("The certificate file can be read by other users. Run: chmod 600 on it.")
    with open(path, "rb") as fh:
        pem = fh.read()
    try:
        key = serialization.load_pem_private_key(pem, password=None)
        cert = x509.load_pem_x509_certificate(pem)
    except ValueError:
        raise GraphError("The certificate file must contain the private key and the certificate (PEM).")
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise GraphError("The certificate must use an RSA key of at least 2048 bits.")
    return key, cert


def client_assertion(tenant: str, client_id: str, key, cert, now: float | None = None) -> str:
    now = int(now if now is not None else time.time())
    der = cert.public_bytes(serialization.Encoding.DER)
    thumb = hashes.Hash(hashes.SHA256())
    thumb.update(der)
    header = {"alg": "PS256", "typ": "JWT", "x5t#S256": _b64url(thumb.finalize())}
    claims = {"aud": f"https://{LOGIN_HOST}/{tenant}/oauth2/v2.0/token", "iss": client_id, "sub": client_id,
              "jti": str(uuid.uuid4()), "nbf": now, "iat": now, "exp": now + 300}
    signing_input = (_b64url(json.dumps(header, separators=(",", ":")).encode()) + "." +
                     _b64url(json.dumps(claims, separators=(",", ":")).encode()))
    sig = key.sign(signing_input.encode(),
                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    return signing_input + "." + _b64url(sig)


def _post(url: str, body: bytes, headers: dict) -> tuple[int, bytes]:
    """HTTPS POST to an allow-listed Microsoft host only. TLS is verified (Python default)."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise GraphError("Blocked: not an allowed Microsoft address.")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with _opener.open(req, timeout=TIMEOUT) as resp:     # nosec - host allow-listed above, no redirects
            return resp.status, resp.read(65536)
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise GraphError(f"Couldn't reach Microsoft ({type(e).__name__}).")


def _error_code(body: bytes) -> str:
    try:
        data = json.loads(body)
    except ValueError:
        return "unknown"
    err = data.get("error")
    if isinstance(err, dict):
        return str(err.get("code", "unknown"))[:80]
    return str(err or "unknown")[:80]


def _access_token() -> str:
    cfg = current_app.config
    ident = (cfg["M365_TENANT_ID"], cfg["M365_CLIENT_ID"])
    with _token_lock:
        if _token["value"] and _token["for"] == ident and _token["expires"] - 300 > time.time():
            return _token["value"]
        key, cert = _load_credentials(cfg["M365_CERT_PATH"])
        form = urllib.parse.urlencode({
            "client_id": cfg["M365_CLIENT_ID"],
            "scope": f"https://{GRAPH_HOST}/.default",
            "grant_type": "client_credentials",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": client_assertion(cfg["M365_TENANT_ID"], cfg["M365_CLIENT_ID"], key, cert),
        }).encode()
        tenant = urllib.parse.quote(cfg["M365_TENANT_ID"], safe="")
        code, body = _post(f"https://{LOGIN_HOST}/{tenant}/oauth2/v2.0/token", form,
                           {"Content-Type": "application/x-www-form-urlencoded"})
        if code != 200:
            raise GraphError(f"Microsoft sign-in failed (HTTP {code}, {_error_code(body)}).")
        data = json.loads(body)
        _token["value"] = data["access_token"]
        _token["expires"] = time.time() + int(data.get("expires_in", 3600))
        _token["for"] = ident
        return _token["value"]


def send_mail(to: list[str], subject: str, body_text: str, cc: list[str] | None = None,
              bcc: list[str] | None = None, attachments: list[tuple[str, bytes]] | None = None) -> None:
    """Send one plain-text email from billing@. Raises GraphError on any failure."""
    if not configured():
        raise GraphError("Email isn't set up yet (Settings → Email).")
    total = sum(len(data) for _, data in (attachments or []))
    if total > MAX_ATTACHMENT_BYTES:
        raise GraphError("Attachment too large.")
    message = {
        "subject": subject,
        "body": {"contentType": "Text", "content": body_text},
        "toRecipients": [{"emailAddress": {"address": a}} for a in to],
        "ccRecipients": [{"emailAddress": {"address": a}} for a in (cc or [])],
        "bccRecipients": [{"emailAddress": {"address": a}} for a in (bcc or [])],
        "attachments": [{"@odata.type": "#microsoft.graph.fileAttachment", "name": name,
                         "contentType": "application/pdf", "contentBytes": base64.b64encode(data).decode()}
                        for name, data in (attachments or [])],
    }
    sender = urllib.parse.quote(current_app.config["M365_SENDER"], safe="@.")
    for attempt in (1, 2):
        token = _access_token()
        code, body = _post(f"https://{GRAPH_HOST}/v1.0/users/{sender}/sendMail",
                           json.dumps({"message": message, "saveToSentItems": True}).encode(),
                           {"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        if code == 202:
            return
        if code == 401 and attempt == 1:          # token expired/revoked: get a fresh one once
            with _token_lock:
                _token["value"] = None
            continue
        raise GraphError(f"Microsoft refused the email (HTTP {code}, {_error_code(body)}).")
