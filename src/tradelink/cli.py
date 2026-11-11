"""Administrative CLI: seed safe demo accounts, run lab exercises, launch local API."""
import argparse
import json
from pathlib import Path

from .app import create_app
from .auth import password_hash
from .detection import RULES, detect
from .store import connect, initialize, log


DEMO_PASSWORD = "TradeLink-Demo-Only!"


def seed(db_path):
    initialize(db_path)
    with connect(db_path) as db:
        for name, role, tenant in (
            ("pacific-buyer", "buyer", "pacific"),
            ("pacific-supplier", "supplier", "pacific"),
            ("atlantic-buyer", "buyer", "atlantic"),
            ("atlantic-supplier", "supplier", "atlantic"),
            ("soc-analyst", "analyst", "security"),
            ("security-admin", "admin", "security"),
        ):
            if not db.execute("SELECT 1 FROM users WHERE username=?", (name,)).fetchone():
                db.execute(
                    "INSERT INTO users(username,password_hash,role,tenant_id) VALUES(?,?,?,?)",
                    (name, password_hash(DEMO_PASSWORD), role, tenant),
                )
        for id_, tenant, name in ((101, "pacific", "USB-C Adapter"), (202, "atlantic", "Solar Charger")):
            db.execute(
                "INSERT OR IGNORE INTO products(id,tenant_id,name,price_cents) VALUES(?,?,?,?)",
                (id_, tenant, name, 2499),
            )
        for id_, tenant, product in ((1001, "pacific", 101), (2002, "atlantic", 202)):
            db.execute(
                "INSERT OR IGNORE INTO orders(id,tenant_id,product_id,quantity) VALUES(?,?,?,?)",
                (id_, tenant, product, 2),
            )


def summarize(db_path):
    with connect(db_path) as db:
        new = detect(db)
        alerts = [dict(r) for r in db.execute("SELECT id,rule_id,severity,title,actor FROM alerts ORDER BY id")]
        cases = [dict(r) for r in db.execute("SELECT id,alert_id,status FROM cases ORDER BY id")]
    return {"new_alerts": new, "alerts": alerts, "cases": cases}


def main():
    parser = argparse.ArgumentParser(description="TradeLink enterprise security lab")
    parser.add_argument("--db", type=Path, default=Path("instance/tradelink.sqlite3"))
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    sub.add_parser("seed")
    sub.add_parser("demo")
    sub.add_parser("detect")
    serve = sub.add_parser("serve")
    serve.add_argument("--port", type=int, default=5000)
    serve.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    if args.command == "init":
        initialize(args.db)
        print(f"Initialized {args.db}")
    elif args.command == "seed":
        seed(args.db)
        print(f"Seeded synthetic users and orders in {args.db}")
        print("DEMO ACCOUNTS ONLY; password:", DEMO_PASSWORD)
    elif args.command == "demo":
        from .scenarios import exercise
        seed(args.db)
        print(json.dumps(exercise(str(args.db)), indent=2))
    elif args.command == "detect":
        initialize(args.db)
        print(json.dumps(summarize(args.db), indent=2))
    else:
        app = create_app({"DATABASE": str(args.db)})
        app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
