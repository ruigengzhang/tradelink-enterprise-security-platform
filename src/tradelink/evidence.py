"""Export auditable JSONL evidence (no session tokens) from the local lab store."""
import argparse
import json
from pathlib import Path
from .store import connect


def export(db_path, destination):
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    with connect(db_path) as db:
        rows = db.execute("SELECT * FROM events ORDER BY id").fetchall()
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            event = dict(row)
            event["meta"] = json.loads(event.pop("meta_json"))
            f.write(json.dumps(event, sort_keys=True) + "\n")
    return len(rows)


def main():
    p = argparse.ArgumentParser(description="Export synthetic audit evidence as NDJSON")
    p.add_argument("--db", default="instance/tradelink.sqlite3")
    p.add_argument("--output", default="artifacts/audit-events.jsonl")
    args = p.parse_args()
    print(f"Exported {export(args.db, args.output)} events to {args.output}")


if __name__ == "__main__":
    main()
