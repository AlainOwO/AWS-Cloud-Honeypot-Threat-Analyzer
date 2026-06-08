# AWS Cloud Honeypot & Threat Intelligence Tracker

## 📌 Project Overview
This project involves the deployment of a customized, interactive SSH honeypot (Cowrie) within an isolated AWS Virtual Private Cloud (VPC). The objective was to attract, log, and analyze real-world brute-force attacks and malware delivery attempts from automated botnets on the public internet.

## 🛠️ Technology Stack
* **Cloud Infrastructure:** AWS (EC2, VPC, Security Groups)
* **Operating System:** Ubuntu Linux 24.04 LTS
* **Honeypot Framework:** Cowrie (Python-based interactive shell environment)
* **Networking:** `iptables` for silent port forwarding (Port 22 -> 2222)
* **Data Analysis:** Python (JSON parsing, data extraction)

## 🏗️ Architecture & Configuration
To ensure maximum security and authentic data capture, the architecture was designed with the following parameters:
1. **Admin Isolation:** True administrative SSH access was migrated to a non-standard port (65222) and restricted via AWS Security Groups to accept connections only from a trusted IP address.
2. **The Trap:** Incoming traffic on the default SSH port (22) was silently routed to the Cowrie honeypot running in a restricted user environment.
3. **Deception:** The honeypot was configured with a simulated Debian filesystem and realistic hostnames to delay attacker detection and capture maximum payload commands.

## 📊 Threat Intelligence Analysis
I developed a custom Python script (`analyze_threats.py`) to parse the structured `cowrie.json` logs. After running the server for several days, the script extracted the following Indicators of Compromise (IoCs):

### Top 5 Attacker IP Addresses
*(I will update this section with real data once the honeypot runs for a few days)*
1. `IP_ADDRESS` - `COUNT` attempts
2. `IP_ADDRESS` - `COUNT` attempts

### Top 5 Guessed Credentials
*(I will update this section with real data once the honeypot runs for a few days)*
1. `root` / `password` - `COUNT` attempts
2. `admin` / `123456` - `COUNT` attempts

## 💡 Key Learnings
* Gained hands-on experience configuring AWS network boundaries and security groups.
* Deepened understanding of Linux user privileges, daemon processes, and `iptables` routing.
* Successfully automated the parsing of complex JSON security logs using Python.
