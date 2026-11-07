"""R12 OFFLINE one-time enrollment of a synthetic KEK rotation witness.

Local POSIX operator only; this is not recovery escrow or a production KMS.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .envelope_rotation_fence import enroll_rotation_witness
from .tenant_store import LocalTenantStore, LocalTenantConfigError


def main(argv=None):
    parser = argparse.ArgumentParser(description="Enroll independent KEK rotation epoch witness")
    parser.add_argument("--db", required=True)
    parser.add_argument("--active-key", required=True)
    parser.add_argument("--rotation-witness", required=True)
    parser.add_argument("--tenant-fence", help="Existing R9 tenant revocation witness")
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args(argv)
    if (os.environ.get("PHICLOUD_ROTATION_WITNESS_OPERATOR_DEV") != "1"
            or os.environ.get("NODE_ENV") == "production"
            or os.environ.get("PHICLOUD_ENV") == "production"
            or args.confirm != "ENROLL SYNTHETIC KEY ROTATION WITNESS"):
        print("DENY: independent local witness enrollment confirmation required",
              file=sys.stderr)
        return 2
    try:
        db_path = Path(args.db)
        if (not db_path.is_absolute() or db_path.is_symlink()
                or not db_path.is_file()):
            raise LocalTenantConfigError("existing_private_database_required")
        store = LocalTenantStore(db_path, fence_path=args.tenant_fence)
        try:
            result = enroll_rotation_witness(store, args.rotation_witness,
                                             args.active_key)
        finally:
            store.close()
        print("R12 synthetic KEK witness enrolled; "
              f"epoch={result['initial_rotation_epoch']}; no key material returned")
        return 0
    except (LocalTenantConfigError, OSError, ValueError) as exc:
        print("DENY: "+str(exc)[:110], file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
