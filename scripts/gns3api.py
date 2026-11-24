"""Tiny GNS3 v3 API helper used by the build/test scripts (reads admin password from ~/services/gns3/.admin-password)."""
import json, os, urllib.request, urllib.error
BASE = os.environ.get("GNS3_URL", "http://100.99.194.92:3080/v3")
_tok = None
def token():
    global _tok
    if _tok: return _tok
    pwf = os.path.expanduser("~/services/gns3/.admin-password")
    pw = os.environ.get("GNS3_PASSWORD") or (open(pwf).read().strip() if os.path.exists(pwf) else None)
    if not pw:
        raise SystemExit("GNS3 password not found. On the Mac run:\n"
                         "  export GNS3_PASSWORD=\"$(ssh carlos@100.99.194.92 cat ~/services/gns3/.admin-password)\"")
    r = urllib.request.Request(BASE + "/access/users/authenticate", data=json.dumps({"username": os.environ.get("GNS3_USER", "admin"), "password": pw}).encode(), headers={"Content-Type": "application/json"})
    _tok = json.load(urllib.request.urlopen(r))["access_token"]; return _tok
def req(method, path, data=None, timeout=180):
    r = urllib.request.Request(BASE + path, method=method, data=json.dumps(data).encode() if data is not None else None,
                               headers={"Authorization": "Bearer " + token(), "Content-Type": "application/json"})
    try:
        body = urllib.request.urlopen(r, timeout=timeout).read()
        return json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{method} {path} -> {e.code}: {e.read()[:400]!r}")
