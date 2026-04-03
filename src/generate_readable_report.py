import pandas as pd
from pathlib import Path

INPUT = Path("../output/suspicious_events.csv")
OUTPUT = Path("../output/summary_readable.txt")

def generate_report():
    df = pd.read_csv(INPUT)

    with open(OUTPUT, "w", encoding="utf-8") as f:
        f.write("====== Suspicious Activity Summary ======\n\n")

        if df.empty:
            f.write("No suspicious activity detected.\n")
            return

        for i, row in df.iterrows():
            f.write(f"Event {i+1}\n")
            f.write(f"Type: {row.get('type', 'Unknown')}\n")
            f.write(f"Username: {row.get('username', 'Unknown')}\n")

            if 'failed_attempts' in row:
                f.write(f"Failed Attempts: {row.get('failed_attempts', 0)}\n")

            if 'timestamp' in row:
                f.write(f"Time: {row.get('timestamp', 'N/A')}\n")

            f.write("---------------------------------------\n\n")

    print(f"Readable summary generated at: {OUTPUT.resolve()}")

if __name__ == "__main__":
    generate_report()
