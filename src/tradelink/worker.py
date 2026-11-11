"""On-demand or periodic detector worker; never executes response automatically."""
import argparse
import time
from .detection import detect
from .store import connect, initialize


def run_once(path):
    initialize(path)
    with connect(path) as conn:
        return detect(conn)


def main():
    p = argparse.ArgumentParser(description="TradeLink periodic detection worker")
    p.add_argument("--db", default="instance/tradelink.sqlite3")
    p.add_argument("--interval", type=int, default=10)
    p.add_argument("--once", action="store_true")
    args = p.parse_args()
    if not 1 <= args.interval <= 3600:
        p.error("interval must be between 1 and 3600 seconds")
    if args.once:
        print(f"New alerts: {run_once(args.db)}")
        return
    print("Continuous detection enabled; response actions require separate approval", flush=True)
    try:
        while True:
            print(f"New alerts: {run_once(args.db)}", flush=True)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("Stopped detector worker")


if __name__ == "__main__":
    main()
