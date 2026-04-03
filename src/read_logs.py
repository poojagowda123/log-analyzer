from pathlib import Path

log_folder = Path("../data/logs")

print("Looking for log files in:", log_folder.resolve())

if not log_folder.exists():
    print("Folder does NOT exist!")
else:
    print("✔ Folder found!")

def read_logs():
    files = list(log_folder.glob("*.log"))
    
    if not files:
        print("No .log files found in the folder.")
        return
    
    for file in files:
        print(f"\n📄 Reading file: {file.name}")
        with open(file, "r") as f:
            for line in f:
                print("→", line.strip())

if __name__ == "__main__":
    read_logs()
