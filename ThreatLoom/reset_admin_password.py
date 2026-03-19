"""
ThreatLoom — emergency admin password reset.
Run from the ThreatLoom/ directory with the venv active:

    python reset_admin_password.py
"""
import sqlite3
import sys
from pathlib import Path

DB_PATH = Path(__file__).parent / "threatloom.db"


def _build_hasher():
    """
    Return a (hash_fn, verify_fn) pair.

    Tries passlib first (used by the main application).  If passlib's bcrypt
    backend is broken — common with bcrypt >= 4.0.0 and passlib 1.7.4 which
    removed the __about__ attribute — we fall back to calling bcrypt directly.
    Both produce compatible $2b$ hashes that the app can verify.
    """
    # --- attempt 1: passlib ---
    try:
        from passlib.context import CryptContext
        ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
        # Quick smoke-test: make sure it can actually hash
        ctx.hash("probe")
        return ctx.hash, ctx.verify
    except Exception:
        pass

    # --- attempt 2: bcrypt directly ---
    try:
        import bcrypt as _bcrypt

        def _hash(password: str) -> str:
            return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt(rounds=12)).decode()

        def _verify(password: str, hashed: str) -> bool:
            return _bcrypt.checkpw(password.encode(), hashed.encode())

        print("[WARN] passlib is incompatible with the installed bcrypt version.")
        print("       Using bcrypt directly — the hash will still work with the app.")
        return _hash, _verify
    except ImportError:
        pass

    print("[ERROR] Neither passlib nor bcrypt is available.")
    print("        Activate the venv first:  venv\\Scripts\\activate")
    sys.exit(1)


def main():
    if not DB_PATH.exists():
        print(f"[ERROR] Database not found: {DB_PATH}")
        print("       Make sure you run this from the ThreatLoom/ directory.")
        sys.exit(1)

    hash_password, _ = _build_hasher()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Show all existing users
    rows = cur.execute("SELECT id, username, role, is_active FROM users").fetchall()
    if not rows:
        print("[INFO] No users found in the database.")
        print("       ThreatLoom has not been bootstrapped yet — just open")
        print("       http://localhost:8443/login to create the first admin account.")
        conn.close()
        return

    print("\nExisting users:")
    print(f"  {'ID':<5} {'Username':<20} {'Role':<15} {'Active'}")
    print(f"  {'-'*5} {'-'*20} {'-'*15} {'-'*6}")
    for uid, uname, role, active in rows:
        print(f"  {uid:<5} {uname:<20} {role:<15} {bool(active)}")

    print()
    target = input("Enter the username to reset (default: admin): ").strip() or "admin"

    row = cur.execute(
        "SELECT id FROM users WHERE username = ?", (target,)
    ).fetchone()
    if not row:
        print(f"[ERROR] User '{target}' not found.")
        conn.close()
        sys.exit(1)

    import getpass
    while True:
        new_pw = getpass.getpass(f"New password for '{target}' (min 12 chars): ")
        if len(new_pw) < 12:
            print("  Password must be at least 12 characters. Try again.")
            continue
        confirm = getpass.getpass("Confirm new password: ")
        if new_pw != confirm:
            print("  Passwords do not match. Try again.")
            continue
        break

    hashed = hash_password(new_pw)
    cur.execute(
        "UPDATE users SET hashed_password = ?, is_active = 1 WHERE username = ?",
        (hashed, target),
    )
    conn.commit()
    conn.close()

    print(f"\n[OK] Password for '{target}' has been reset.")
    print("     You can now log in at http://localhost:8443/login")


if __name__ == "__main__":
    main()
