import json
import glob
import argparse
from collections import Counter

def analyze(log_pattern: str):
    ips = []
    credentials = []

    log_files = sorted(glob.glob(log_pattern))

    if not log_files:
        print(f"Error: No log files matched pattern: {log_pattern}")
        print("Check the path -- e.g. ~/cowrie/var/log/cowrie/cowrie.json*")
        return

    print(f"Analyzing {len(log_files)} log file(s): {', '.join(log_files)}\n")

    for log_file in log_files:
        try:
            with open(log_file, "r") as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())

                        # Track every time an IP connects
                        if data.get("eventid") == "cowrie.session.connect":
                            ips.append(data.get("src_ip"))

                        # Track usernames and passwords from login attempts
                        if data.get("eventid") in ["cowrie.login.failed", "cowrie.login.success"]:
                            user = data.get("username", "UNKNOWN")
                            pw = data.get("password", "UNKNOWN")
                            credentials.append(f"{user}:{pw}")

                    except json.JSONDecodeError:
                        # Skip any corrupted lines
                        continue

        except FileNotFoundError:
            print(f"Warning: Could not open {log_file}, skipping.")
            continue

    # Calculate the top 10 most common items
    top_ips = Counter(ips).most_common(10)
    top_creds = Counter(credentials).most_common(10)

    # Print the results
    print("=== TOP 10 ATTACKER IPs ===")
    for ip, count in top_ips:
        print(f"{ip}: {count} connections")

    print("\n=== TOP 10 GUESSED CREDENTIALS ===")
    for cred, count in top_creds:
        print(f"{cred}: {count} attempts")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Summarize Cowrie honeypot logs (IPs + credentials).")
    parser.add_argument(
        "--log-pattern",
        default="~/cowrie/var/log/cowrie/cowrie.json*",
        help=(
            "Glob pattern matching Cowrie JSON log(s). Defaults to the standard "
            "Cowrie install path, including rotated daily logs (cowrie.json.YYYY-MM-DD). "
            "Adjust if your install path differs."
        ),
    )
    args = parser.parse_args()

    # Expand ~ to home directory
    import os
    pattern = os.path.expanduser(args.log_pattern)
    analyze(pattern)
