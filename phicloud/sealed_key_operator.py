"""Opt-in OFFLINE local R10 test-key provisioning; no key is ever printed.

No hosted KMS, recovery escrow, key rotation, real-user data, or PhiVault access.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .sealed_demo import provision_local_key
from .tenant_store import (
    LocalTenantConfigError, _acquire_private_database_lock, _check_db_path
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Create exactly one independent synthetic-marker encryption key")
    parser.add_argument("--db", required=True)
    parser.add_argument("--key-path", required=True)
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args(argv)
    if (os.environ.get("PHICLOUD_SEALED_KEY_OPERATOR_DEV") != "1"
            or os.environ.get("NODE_ENV") == "production"
            or os.environ.get("PHICLOUD_ENV") == "production"
            or args.confirm != "CREATE SYNTHETIC TEST KEY"):
        print("DENY: explicit local synthetic-key provisioning required", file=sys.stderr)
        return 2
    try:
        db = Path(args.db)
        _check_db_path(db)
        if db.is_symlink() or not db.is_file():
            raise LocalTenantConfigError("existing_private_test_database_required")
        lease_fd = _acquire_private_database_lock(db)
        try:
            provision_local_key(args.key_path, db)
        finally:
            os.close(lease_fd)
        print("R10 synthetic private encryption key created; key bytes not displayed")
        return 0
    except (LocalTenantConfigError, OSError, ValueError) as exc:
        # Static-code failure only, never print secret or full file path.
        print("DENY: " + str(exc)[:100], file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
