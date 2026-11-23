"""The only way the app talks to the internet: HTTPS POST to an allow-listed host,
TLS verified, no redirects (credentials can never follow one elsewhere), and no
proxy picked up from environment variables."""
import http.client
import urllib.error
import urllib.parse
import urllib.request

TIMEOUT = 20


class OutboundError(Exception):
    """Safe to show and log: never contains secrets or content."""


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise OutboundError(f"Blocked: the service answered with a redirect (HTTP {code}).")


opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirects())


def post(url: str, body: bytes, headers: dict, allowed_hosts: set[str], timeout: int = TIMEOUT) -> tuple[int, bytes]:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError:
        raise OutboundError("Blocked: not a valid address.")
    if (parsed.scheme != "https" or parsed.hostname not in allowed_hosts or "@" in parsed.netloc
            or port is not None or parsed.netloc != parsed.hostname):
        raise OutboundError("Blocked: not an allowed address.")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with opener.open(req, timeout=timeout) as resp:    # nosec - host allow-listed above
            return resp.status, resp.read(65536)
    except urllib.error.HTTPError as e:
        return e.code, e.read(65536)
    except OutboundError:
        raise
    except (urllib.error.URLError, http.client.HTTPException, ValueError, TimeoutError, OSError) as e:
        raise OutboundError(f"Couldn't reach the service ({type(e).__name__}).")
