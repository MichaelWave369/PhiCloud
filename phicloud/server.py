"""Local-only R0 HTTP manifest viewer; no remote probes, account or action APIs."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .registry import ManifestError, load_manifest
from .authz import (
    AuthorizationDenied, AuthorizationUnavailable,
    create_local_introspector, validate_bearer_header,
)

DEFAULT_MANIFEST = Path(__file__).resolve().parent.parent / "config" / "services.json"
LOOPBACK = "127.0.0.1"


def make_handler(manifest: dict, authorizer=None):
    """Factory returns a request handler with a validated, immutable startup snapshot."""
    snapshot = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def _reply(self, code: int, payload: bytes) -> None:
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:  # noqa: N802 (standard library hook)
            requested = urlsplit(self.path)
            if requested.query or requested.fragment:
                self._reply(404, b'{"error":"not_found"}')
            elif requested.path == "/healthz":
                self._reply(200, b'{"status":"ok","scope":"local_registry_process_only"}')
            elif requested.path == "/v1/services":
                # The entries are *declarations*, not runtime status reports.
                self._reply(200, snapshot)
            elif requested.path == "/v1/private/profile" and authorizer is not None:
                self._private_profile()
            else:
                self._reply(404, b'{"error":"not_found"}')

        def _private_profile(self) -> None:
            """One read-only resource: actual server-side introspection each time.

            No profile input, no credentials accepted in query/body, no remote
            storage and no meaningful permissions for anything outside here.
            """
            peer = self.client_address[0]
            hosts = self.headers.get_all("Host", [])
            expected_host = f"{LOOPBACK}:{self.server.server_port}"
            if peer != LOOPBACK or len(hosts) != 1 or hosts[0] != expected_host:
                self._reply(403, b'{"error":"local_host_required"}')
                return
            if self.headers.get("Sec-Fetch-Site") == "cross-site":
                self._reply(403, b'{"error":"cross_site_access_denied"}')
                return
            try:
                token = validate_bearer_header(self.headers.get_all("Authorization"))
                principal = authorizer.authorize(token)
            except AuthorizationDenied:
                self._reply(401, b'{"error":"invalid_or_insufficient_access_token"}')
                return
            except AuthorizationUnavailable:
                # No cached positive decisions. Fail closed if Keycloak fails.
                self._reply(503, b'{"error":"identity_provider_unavailable"}')
                return
            except Exception:
                # No secrets or user identifiers are ever logged.
                self._reply(503, b'{"error":"authorization_unavailable"}')
                return
            payload = json.dumps(
                principal.public_profile(), sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            self._reply(200, payload)

        def log_message(self, format: str, *args: object) -> None:
            # No request bodies or credentials are accepted in this read-only prototype.
            return

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PhiCloud read-only LOCAL registry (R0)")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--port", type=int, default=8769)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be 1..65535")
    try:
        manifest = load_manifest(args.manifest)
    except ManifestError as exc:
        parser.error(str(exc))
    # Always bind to IPv4 loopback; never accept --host in this prototype.
    # Only explicit local opt-in enables the *separate* protected route.
    try:
        authorizer = create_local_introspector()
    except ValueError as exc:
        parser.error(str(exc))
    with ThreadingHTTPServer((LOOPBACK, args.port), make_handler(manifest, authorizer)) as server:
        print(f"PhiCloud R0: http://{LOOPBACK}:{args.port}/v1/services (declarative only)")
        print("Local R3 OAuth test route enabled" if authorizer else "R3 OAuth test route disabled")
        print("No hosted accounts, mail delivery, remote service discovery or cloud storage.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
