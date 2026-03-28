import os
import time
import hashlib
import sqlite3
import argparse
from pathlib import Path
from datetime import datetime

# ──────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────
DB_FILE           = "baseline.db"
DEFAULT_WATCH_DIR = "watched_files"
CHECK_INTERVAL    = 10  # seconds

# ──────────────────────────────────────────
# DATABASE
# ──────────────────────────────────────────
def init_db(db_path):
    """Create database and tables if they don't exist."""
    conn = sqlite3.connect(db_path)
    cur  = conn.cursor()

    # Baseline table — stores original file hashes
    cur.execute("""
        CREATE TABLE IF NOT EXISTS baseline (
            filepath TEXT PRIMARY KEY,
            hash     TEXT NOT NULL,
            size     INTEGER,
            saved_at TEXT
        )
    """)

    # Events table — stores all detected changes
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type  TEXT,
            filepath    TEXT,
            detected_at TEXT
        )
    """)

    conn.commit()
    return conn


# ──────────────────────────────────────────
# HASHING
# ──────────────────────────────────────────
def hash_file(filepath):
    """Calculate SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (IOError, PermissionError):
        return None


# ──────────────────────────────────────────
# BASELINE
# ──────────────────────────────────────────
def create_baseline(watch_dir, conn):
    """Scan directory and save hash of every file as baseline."""
    cur   = conn.cursor()
    path  = Path(watch_dir)
    files = list(path.rglob("*"))
    count = 0

    print(f"\n[*] Creating baseline for: {watch_dir}")

    for f in files:
        if f.is_file():
            file_hash = hash_file(f)
            if file_hash:
                cur.execute("""
                    INSERT OR REPLACE INTO baseline
                    (filepath, hash, size, saved_at)
                    VALUES (?, ?, ?, ?)
                """, (
                    str(f),
                    file_hash,
                    f.stat().st_size,
                    datetime.now().isoformat()
                ))
                count += 1

    conn.commit()
    print(f"[✓] Baseline created — {count} files saved\n")


def load_baseline(conn):
    """Load baseline from database into a dictionary."""
    cur = conn.cursor()
    cur.execute("SELECT filepath, hash FROM baseline")
    return {row[0]: row[1] for row in cur.fetchall()}


# ──────────────────────────────────────────
# MONITORING
# ──────────────────────────────────────────
def log_event(conn, event_type, filepath):
    """Save a detected event to the database."""
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO events (event_type, filepath, detected_at)
        VALUES (?, ?, ?)
    """, (event_type, filepath, datetime.now().isoformat()))
    conn.commit()


def check_integrity(watch_dir, baseline, conn):
    """
    Compare current files against baseline.
    Detect: MODIFIED, DELETED, ADDED
    """
    path          = Path(watch_dir)
    current_files = {str(f): hash_file(f) for f in path.rglob("*") if f.is_file()}
    alerts        = []

    # Check for MODIFIED or DELETED files
    for filepath, original_hash in baseline.items():
        if filepath not in current_files:
            alerts.append(("DELETED", filepath))
        elif current_files[filepath] != original_hash:
            alerts.append(("MODIFIED", filepath))

    # Check for ADDED files
    for filepath in current_files:
        if filepath not in baseline:
            alerts.append(("ADDED", filepath))

    return alerts


def print_alert(event_type, filepath):
    """Print a formatted alert to the terminal."""
    icons = {
        "MODIFIED": "⚠️  MODIFIED",
        "DELETED":  "🚨 DELETED ",
        "ADDED":    "ℹ️  ADDED   ",
    }
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"  [{timestamp}] {icons[event_type]} → {filepath}")


# ──────────────────────────────────────────
# MAIN MONITOR LOOP
# ──────────────────────────────────────────
def start_monitor(watch_dir, conn, interval):
    """Main loop — checks integrity every X seconds."""
    baseline = load_baseline(conn)

    if not baseline:
        print("[ERROR] Baseline is empty. Run with --baseline first.")
        return

    print(f"[*] Monitoring: {watch_dir}")
    print(f"[*] Check every: {interval} seconds")
    print(f"[*] Press Ctrl+C to stop\n")
    print("─" * 55)

    try:
        while True:
            alerts = check_integrity(watch_dir, baseline, conn)

            if alerts:
                for event_type, filepath in alerts:
                    print_alert(event_type, filepath)
                    log_event(conn, event_type, filepath)

                    # Update baseline for MODIFIED and ADDED
                    if event_type in ("MODIFIED", "ADDED"):
                        new_hash = hash_file(filepath)
                        if new_hash:
                            baseline[filepath] = new_hash
                    elif event_type == "DELETED":
                        baseline.pop(filepath, None)
            else:
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"  [{timestamp}] ✓ All files intact", end="\r")

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n\n[*] Monitor stopped.")
        show_history(conn)


# ──────────────────────────────────────────
# HISTORY
# ──────────────────────────────────────────
def show_history(conn):
    """Print all recorded events from the database."""
    cur = conn.cursor()
    cur.execute("SELECT event_type, filepath, detected_at FROM events ORDER BY detected_at")
    rows = cur.fetchall()

    print("\n" + "═" * 55)
    print("         📋 EVENT HISTORY")
    print("═" * 55)

    if rows:
        for event_type, filepath, detected_at in rows:
            icons = {"MODIFIED": "⚠️ ", "DELETED": "🚨", "ADDED": "ℹ️ "}
            print(f"  {icons.get(event_type,'?')} {event_type:<10} {detected_at[11:19]}  {filepath}")
    else:
        print("  No events recorded.")

    print("═" * 55)


# ──────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="File Integrity Monitor")
    parser.add_argument("--dir",      default=DEFAULT_WATCH_DIR, help="Directory to monitor")
    parser.add_argument("--baseline", action="store_true",        help="Create baseline snapshot")
    parser.add_argument("--monitor",  action="store_true",        help="Start monitoring")
    parser.add_argument("--history",  action="store_true",        help="Show event history")
    parser.add_argument("--interval", type=int, default=CHECK_INTERVAL)
    args = parser.parse_args()

    conn = init_db(DB_FILE)

    # Create the watch directory if it doesn't exist
    Path(args.dir).mkdir(exist_ok=True)

    if args.baseline:
        create_baseline(args.dir, conn)

    elif args.monitor:
        start_monitor(args.dir, conn, args.interval)

    elif args.history:
        show_history(conn)

    else:
        print("Usage:")
        print("  python fim.py --baseline          # create snapshot")
        print("  python fim.py --monitor           # start monitoring")
        print("  python fim.py --history           # show all events")
        print("  python fim.py --dir C:\\sensitive  # custom directory")


if __name__ == "__main__":
    main()