import json
from collections import Counter

# Path to the Cowrie JSON log
log_file = "var/log/cowrie/cowrie.json"

ips = []
credentials = []

print("Analyzing honeypot logs...\n")

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

except FileNotFoundError:
    print(f"Error: Could not find the log file at {log_file}")
    print("Make sure you are running this from the ~/cowrie directory.")
