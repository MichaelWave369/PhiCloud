"""R9 trusted OFFLINE enrollment and revoke-only recovery for local test tenants.

This command NEVER creates tenant membership, issues OAuth tokens, restores
deleted content, or connects to real user data. It cannot be called over HTTP.
Use it only on disposable local dev SQLite and an independent private witness.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .tenant_store import LocalTenantConfigError, LocalTenantStore
from .tenant_fence import WitnessError

REQUEST_SCHEMA = "phicloud.tenant-recovery-operator/0.1"
MAX_INPUT_BYTES = 512
EXPECTED = {
    "enroll": "ENROLL INDEPENDENT WITNESS",
    "reconcile": "RECONCILE REVOKE ONLY",
}


def _unique_pairs(pairs):
    value = {}
    for k, v in pairs:
        if k in value:
            raise ValueError("duplicate_request_field")
        value[k] = v
    return value


def execute(argv=None, *, stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr) -> int:
    parser = argparse.ArgumentParser(
        description="Local-only backup-aware revocation guard for synthetic tenants")
    parser.add_argument("--db", required=True, help="Existing owner-private SQLite fixture")
    parser.add_argument("--witness", required=True,
                        help="Independent private .jsonl (outside SQLite backup directory)")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--enroll", action="store_true")
    mode.add_argument("--reconcile", action="store_true")
    args = parser.parse_args(argv)
    if (os.environ.get("PHICLOUD_TENANT_RECOVERY_DEV") != "1"
            or os.environ.get("NODE_ENV") == "production"
            or os.environ.get("PHICLOUD_ENV") == "production"):
        print("DENY: local recovery opt-in required and production forbidden", file=stderr)
        return 2
    mode_name = "enroll" if args.enroll else "reconcile"
    try:
        raw = stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise LocalTenantConfigError("oversized_recovery_confirmation")
        try:
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        except (ValueError, UnicodeError) as exc:
            raise LocalTenantConfigError("invalid_recovery_confirmation") from exc
        if (not isinstance(data, dict)
                or set(data) != {"schema", "confirmation"}
                or data["schema"] != REQUEST_SCHEMA
                or data["confirmation"] != EXPECTED[mode_name]):
            raise LocalTenantConfigError("explicit_recovery_confirmation_required")
        db = Path(args.db)
        if (not db.is_absolute() or db.suffix != ".sqlite"
                or db.is_symlink() or not db.is_file()):
            raise LocalTenantConfigError("existing_private_database_required")
        store = LocalTenantStore(
            db, fence_path=(args.witness if args.reconcile else None),
            recovery_mode=args.reconcile)
        try:
            if args.enroll:
                result = store.enroll_recovery_fence(args.witness)
            else:
                result = store.reconcile_recovery_fence()
        finally:
            store.close()
        print(json.dumps({
            **result, "mode": mode_name,
            "schema": "phicloud.tenant-recovery-result/0.1",
        }, separators=(",", ":"), sort_keys=True), file=stdout)
        return 0
    except (LocalTenantConfigError, WitnessError, OSError, ValueError) as exc:
        # All emitted error codes are authored by the implementation, not
        # user-supplied file paths or identity IDs.
        print("DENY: " + str(exc)[:110], file=stderr)
        return 2


def main():
    raise SystemExit(execute())


if __name__ == "__main__":
    main()
