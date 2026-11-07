"""R8 OFFLINE operator-only tenant membership removal (development fixture).

Not an authenticated HTTP API, not a user-facing admin console, and not an
IdP logout. The operator is the trusted local OS user controlling the private
SQLite file. A running PhiCloud resource server holds an exclusive lease,
so the command fails closed rather than editing an active database.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

from .tenant_store import (
    LocalTenantConfigError, LocalTenantError, LocalTenantStore,
)

INPUT_SCHEMA = "phicloud.local-tenant-operator-request.v0.1"
OUTPUT_SCHEMA = "phicloud.local-tenant-operator-result.v0.1"
MAX_REQUEST = 4096


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_operator_request_field")
        result[key] = value
    return result


def _read_request(stdin) -> tuple[str, SimpleNamespace, bool]:
    raw = stdin.buffer.read(MAX_REQUEST + 1)
    if len(raw) > MAX_REQUEST:
        raise LocalTenantConfigError("operator_request_too_large")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError) as exc:
        raise LocalTenantConfigError("invalid_operator_request") from exc
    if (not isinstance(data, dict) or
            set(data) != {"schema", "tenant", "member", "acknowledge"} or
            data["schema"] != INPUT_SCHEMA or
            not isinstance(data["member"], dict) or
            set(data["member"]) != {"iss", "sub"}):
        raise LocalTenantConfigError("invalid_operator_request_schema")
    acknowledge = data["acknowledge"]
    if acknowledge is not None and not isinstance(acknowledge, str):
        raise LocalTenantConfigError("invalid_operator_acknowledgment")
    try:
        identity = SimpleNamespace(
            issuer=data["member"]["iss"], sub=data["member"]["sub"])
        # Actual issuer and subject validity are checked by LocalTenantStore.
        tenant = LocalTenantStore._tenant_id(data["tenant"])
    except LocalTenantError as exc:
        raise LocalTenantConfigError("invalid_tenant_selector") from exc
    return tenant, identity, acknowledge == ("REVOKE " + tenant)


def execute(argv=None, *, stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr) -> int:
    parser = argparse.ArgumentParser(
        description="PhiCloud R8: offline LOCAL test-tenant removal only")
    parser.add_argument("--db", required=True,
                        help="Existing private absolute SQLite test database")
    parser.add_argument("--apply", action="store_true",
                        help="Irreversibly revoke only this local membership and purge its synthetic records")
    args = parser.parse_args(argv)

    if (os.environ.get("PHICLOUD_TENANT_OPERATOR_DEV") != "1" or
            os.environ.get("NODE_ENV") == "production" or
            os.environ.get("PHICLOUD_ENV") == "production"):
        print("DENY: local operator opt-in required; production prohibited", file=stderr)
        return 2

    # Never create a fresh empty SQLite database through a destructive tool.
    try:
        path = Path(args.db)
        if (not path.is_absolute() or not path.name.endswith(".sqlite") or
                not path.is_file() or path.is_symlink()):
            raise LocalTenantConfigError("existing_private_database_required")
        tenant, identity, confirmed = _read_request(stdin)
        if args.apply and not confirmed:
            raise LocalTenantConfigError("explicit_tenant_matched_revoke_confirmation_required")
        if (os.environ.get("PHICLOUD_TENANT_FENCE_PATH") and
                os.environ.get("PHICLOUD_ENABLE_FENCE_DEV") != "1"):
            raise LocalTenantConfigError("explicit_recovery_fence_opt_in_required")
        fence_path = (os.environ.get("PHICLOUD_TENANT_FENCE_PATH")
                      if os.environ.get("PHICLOUD_ENABLE_FENCE_DEV") == "1" else None)
        if os.environ.get("PHICLOUD_ENABLE_FENCE_DEV") == "1" and not fence_path:
            raise LocalTenantConfigError("private_recovery_fence_path_required")
        store = LocalTenantStore(path, fence_path=fence_path)
        try:
            if args.apply:
                result = store.revoke_member_offline(tenant, identity)
            else:
                result = store.preview_member_removal(tenant, identity)
        finally:
            store.close()
        print(json.dumps({
            "mode": "apply" if args.apply else "preview",
            # Never echo raw issuer/sub or subject hashes, even to the local CLI.
            **result,
            "schema": OUTPUT_SCHEMA,
        }, sort_keys=True, separators=(",", ":")), file=stdout)
        return 0
    except (LocalTenantConfigError, LocalTenantError, OSError, ValueError) as exc:
        # Errors contain only internally authored static codes, never input.
        print("DENY: " + str(exc)[:120], file=stderr)
        return 2


def main():
    raise SystemExit(execute())


if __name__ == "__main__":
    main()
