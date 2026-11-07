"""R11 offline-only, nonproduction wrapping-key rotation for fixed canaries.

The operator is the trusted local POSIX user controlling the SQLite fixture
and two separately provisioned 0600 wrapping-key files. There is deliberately
no HTTP route, automatic key deletion, or real-data encryption service.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .envelope_demo import rotate_wrapping_key, EnvelopeIntegrityError
from .tenant_store import LocalTenantStore, LocalTenantConfigError


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Rewrap synthetic R11 per-marker DEKs under a new private KEK")
    parser.add_argument("--db", required=True)
    parser.add_argument("--old-key", required=True)
    parser.add_argument("--new-key", required=True)
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--fence", help="Existing independent R9 witness path, if enrolled")
    args = parser.parse_args(argv)
    if (os.environ.get("PHICLOUD_ENVELOPE_OPERATOR_DEV") != "1"
            or os.environ.get("NODE_ENV") == "production"
            or os.environ.get("PHICLOUD_ENV") == "production"
            or args.confirm != "REWRAP SYNTHETIC ENVELOPES"):
        print("DENY: explicit local R11 rotation confirmation required",
              file=sys.stderr)
        return 2
    try:
        database = Path(args.db)
        if not database.is_absolute() or database.is_symlink() or not database.is_file():
            raise LocalTenantConfigError("existing_private_test_database_required")
        store = LocalTenantStore(database, fence_path=args.fence)
        try:
            result = rotate_wrapping_key(store, args.old_key, args.new_key)
        finally:
            store.close()
        # Never echo key material, subject hashes, record IDs or paths.
        print("R11 synthetic wrapping-key rotation committed; "
              f"rewrapped_markers={result['rewrapped_markers']}; "
              "payload_reencrypted=false; old_key_deleted=false")
        return 0
    except (LocalTenantConfigError, EnvelopeIntegrityError, OSError, ValueError) as exc:
        # Errors from called code are static authored tokens, not user input.
        print("DENY: " + str(exc)[:100], file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
