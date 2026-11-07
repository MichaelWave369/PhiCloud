"""Local-only R0 HTTP manifest viewer; no remote probes, account or action APIs."""

from __future__ import annotations

import argparse
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .registry import ManifestError, load_manifest
from .authz import (
    AuthorizationDenied, AuthorizationUnavailable,
    create_local_introspector, validate_bearer_header,
    DEMO_READ_SCOPE, DEMO_WRITE_SCOPE,
)
from .owner_demo import DemoStoreFull, OwnerDemoStore, SCHEMA as OWNER_SCHEMA
from .tenant_store import (LocalTenantError, LocalTenantCapacity, LocalTenantConfigError,
                           create_tenant_store, TENANT_SCHEMA)

DEFAULT_MANIFEST = Path(__file__).resolve().parent.parent / "config" / "services.json"
LOOPBACK = "127.0.0.1"


def make_handler(manifest: dict, authorizer=None, owner_store=None, tenant_store=None):
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
            elif tenant_store is not None and requested.path.startswith("/v1/private/tenants/"):
                self._tenant_read(requested.path)
            elif (owner_store is not None and
                  (requested.path == "/v1/private/demo-records" or
                   requested.path.startswith("/v1/private/demo-records/"))):
                self._demo_read(requested.path)
            else:
                self._reply(404, b'{"error":"not_found"}')

        def do_POST(self) -> None:  # noqa: N802
            requested = urlsplit(self.path)
            if tenant_store is not None and requested.path.startswith("/v1/private/tenants/"):
                if requested.query or requested.fragment:
                    self._reply(404, b'{"error":"not_found"}')
                else:
                    self._tenant_mutation("create", requested.path)
                return
            if (owner_store is None or requested.query or requested.fragment or
                requested.path != "/v1/private/demo-records"):
                self._reply(404, b'{"error":"not_found"}')
                return
            self._demo_mutation("create", None)

        def do_DELETE(self) -> None:  # noqa: N802
            requested = urlsplit(self.path)
            if tenant_store is not None and requested.path.startswith("/v1/private/tenants/"):
                if requested.query or requested.fragment:
                    self._reply(404, b'{"error":"not_found"}')
                else:
                    self._tenant_mutation("delete", requested.path)
                return
            prefix = "/v1/private/demo-records/"
            if (owner_store is None or requested.query or requested.fragment or
                not requested.path.startswith(prefix)):
                self._reply(404, b'{"error":"not_found"}')
                return
            self._demo_mutation("delete", requested.path[len(prefix):])

        def _require_local(self) -> bool:
            peer = self.client_address[0]
            hosts = self.headers.get_all("Host", [])
            expected_host = f"{LOOPBACK}:{self.server.server_port}"
            if peer != LOOPBACK or len(hosts) != 1 or hosts[0] != expected_host:
                self._reply(403, b'{"error":"local_host_required"}')
                return False
            if self.headers.get("Sec-Fetch-Site") == "cross-site":
                self._reply(403, b'{"error":"cross_site_access_denied"}')
                return False
            return True

        def _authorize_demo(self, scope: str):
            try:
                token = validate_bearer_header(self.headers.get_all("Authorization"))
                return authorizer.authorize(token, required_scope=scope)
            except AuthorizationDenied:
                self._reply(401, b'{"error":"invalid_or_insufficient_access_token"}')
            except AuthorizationUnavailable:
                self._reply(503, b'{"error":"identity_provider_unavailable"}')
            except Exception:
                self._reply(503, b'{"error":"authorization_unavailable"}')
            return None

        def _demo_read(self, path: str) -> None:
            if not self._require_local():
                return
            principal = self._authorize_demo(DEMO_READ_SCOPE)
            if principal is None:
                return
            prefix = "/v1/private/demo-records"
            try:
                if path == prefix:
                    records = owner_store.list_own(principal)
                    self._reply(200, json.dumps({
                        "schema": OWNER_SCHEMA, "persistent": False,
                        "owner_isolation_enforced": True, "records": records,
                    }, separators=(",", ":")).encode("utf-8"))
                elif path.startswith(prefix + "/"):
                    record = owner_store.read_own(principal, path[len(prefix) + 1:])
                    if record is None:
                        self._reply(404, b'{"error":"not_found"}')
                        return
                    self._reply(200, json.dumps(record, separators=(",", ":")).encode("utf-8"))
                else:
                    self._reply(404, b'{"error":"not_found"}')
            except Exception:
                self._reply(503, b'{"error":"local_demo_unavailable"}')

        def _demo_mutation(self, action: str, record_id: str | None) -> None:
            if not self._require_local():
                return
            expected_action = ("create-demo-record" if action == "create"
                               else "delete-demo-record")
            origin = self.headers.get_all("Origin", [])
            expected_origin = f"http://{LOOPBACK}:{self.server.server_port}"
            if (len(origin) > 1 or (origin and origin != [expected_origin]) or
                self.headers.get_all("X-PhiCloud-Action", []) != [expected_action]):
                self._reply(403, b'{"error":"explicit_local_action_required"}')
                return
            # These routes accept NO caller-controlled payload or owner field.
            # Reject transfer encoding, body and media type, rather than
            # accidentally leaving unread bytes on a keepalive connection.
            length = self.headers.get_all("Content-Length", [])
            if (self.headers.get_all("Transfer-Encoding") or
                len(length) > 1 or (length and length != ["0"]) or
                self.headers.get_all("Content-Type")):
                self._reply(413, b'{"error":"body_not_accepted"}')
                self.close_connection = True
                return
            principal = self._authorize_demo(DEMO_WRITE_SCOPE)
            if principal is None:
                return
            try:
                if action == "create":
                    record = owner_store.create(principal)
                    self._reply(201, json.dumps(record, separators=(",", ":")).encode("utf-8"))
                elif action == "delete":
                    removed = owner_store.delete_own(principal, record_id or "")
                    if not removed:
                        self._reply(404, b'{"error":"not_found"}')
                    else:
                        self._reply(200, b'{"deleted":true,"persistent":false}')
                else:
                    self._reply(404, b'{"error":"not_found"}')
            except DemoStoreFull:
                self._reply(429, b'{"error":"local_demo_capacity"}')
            except Exception:
                self._reply(503, b'{"error":"local_demo_unavailable"}')

        def _parse_tenant_resource(self, path: str):
            # Only fixed metadata endpoints; never accept path traversal,
            # arbitrary file paths, client-specified owner, or query payloads.
            match = re.fullmatch(
                r"/v1/private/tenants/([a-z][a-z0-9-]{2,31})/"
                r"(records|audit)(?:/([A-Za-z0-9_-]{24,64}))?", path
            )
            if not match:
                return None
            tenant_id, category, record_id = match.groups()
            if category == "audit" and record_id is not None:
                return None
            return tenant_id, category, record_id

        def _tenant_read(self, path: str) -> None:
            parsed = self._parse_tenant_resource(path)
            if parsed is None:
                self._reply(404, b'{"error":"not_found"}')
                return
            if not self._require_local():
                return
            principal = self._authorize_demo("phicloud.tenant.read")
            if principal is None:
                return
            tenant_id, category, record_id = parsed
            try:
                if category == "audit":
                    events = tenant_store.own_audit(principal, tenant_id)
                    reply = {"schema": TENANT_SCHEMA, "tenant": tenant_id,
                             "actor_isolated": True, "events": events}
                    self._reply(200, json.dumps(reply, separators=(",", ":")).encode())
                elif record_id is None:
                    records = tenant_store.list_own(principal, tenant_id)
                    reply = {"schema": TENANT_SCHEMA, "tenant": tenant_id,
                             "persistent_local_only": True, "records": records}
                    self._reply(200, json.dumps(reply, separators=(",", ":")).encode())
                else:
                    record = tenant_store.read_own(principal, tenant_id, record_id)
                    if record is None:
                        self._reply(404, b'{"error":"not_found"}')
                    else:
                        self._reply(200, json.dumps(record, separators=(",", ":")).encode())
            except LocalTenantError:
                self._reply(404, b'{"error":"not_found"}')
            except Exception:
                self._reply(503, b'{"error":"local_tenant_unavailable"}')

        def _tenant_mutation(self, action: str, path: str) -> None:
            parsed = self._parse_tenant_resource(path)
            if parsed is None:
                self._reply(404, b'{"error":"not_found"}')
                return
            tenant_id, category, record_id = parsed
            if (category != "records" or
                (action == "create" and record_id is not None) or
                (action == "delete" and record_id is None)):
                self._reply(404, b'{"error":"not_found"}')
                return
            if not self._require_local():
                return
            expected_action = ("create-tenant-test-record" if action == "create"
                               else "delete-tenant-test-record")
            origin = self.headers.get_all("Origin", [])
            expected_origin = f"http://{LOOPBACK}:{self.server.server_port}"
            if (len(origin) > 1 or (origin and origin != [expected_origin]) or
                self.headers.get_all("X-PhiCloud-Action", []) != [expected_action]):
                self._reply(403, b'{"error":"explicit_local_action_required"}')
                return
            length = self.headers.get_all("Content-Length", [])
            if (self.headers.get_all("Transfer-Encoding") or
                len(length) > 1 or (length and length != ["0"]) or
                self.headers.get_all("Content-Type")):
                self._reply(413, b'{"error":"body_not_accepted"}')
                self.close_connection = True
                return
            principal = self._authorize_demo("phicloud.tenant.write")
            if principal is None:
                return
            try:
                if action == "create":
                    record = tenant_store.create(principal, tenant_id)
                    self._reply(201, json.dumps(record, separators=(",", ":")).encode())
                else:
                    tenant_store.delete_own(principal, tenant_id, record_id)
                    self._reply(200, b'{"deleted":true,"durable_audit_retained":true}')
            except LocalTenantError:
                self._reply(404, b'{"error":"not_found"}')
            except LocalTenantCapacity:
                self._reply(429, b'{"error":"local_tenant_capacity"}')
            except Exception:
                self._reply(503, b'{"error":"local_tenant_unavailable"}')

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
    demo_requested = os.environ.get("PHICLOUD_ENABLE_OWNER_DEMO") == "1"
    if demo_requested and authorizer is None:
        parser.error("owner_demo_requires_explicit_oauth_gate")
    owner_store = OwnerDemoStore() if demo_requested else None
    try:
        tenant_store = create_tenant_store()
    except (LocalTenantConfigError, ValueError) as exc:
        parser.error(str(exc))
    try:
        server = ThreadingHTTPServer((LOOPBACK, args.port),
                make_handler(manifest, authorizer, owner_store, tenant_store))
    except Exception:
        if tenant_store:
            tenant_store.close()
        raise
    with server:
        print(f"PhiCloud R0: http://{LOOPBACK}:{args.port}/v1/services (declarative only)")
        print("Local R3 OAuth test route enabled" if authorizer else "R3 OAuth test route disabled")
        print("R4 ephemeral owner isolation demo enabled" if owner_store else "R4 owner demo disabled")
        print("R6 private synthetic tenant store enabled" if tenant_store else "R6 tenant store disabled")
        print("No hosted accounts, mail delivery, remote service discovery or cloud storage.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
    if tenant_store:
        tenant_store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
