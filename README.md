# AWS Cloud Honeypot & Threat Intelligence Tracker

## ⚠️ Status
This honeypot was deployed and actively ran on a student AWS account, capturing 1,000+ malicious requests over its runtime. That account has since been closed by the university (standard student-account lifecycle), so the original live logs are no longer retrievable. The analysis and AI-classification scripts below are fully functional and verified against bundled sample sessions (`--demo` mode) — re-deploying on a fresh AWS/Oracle Cloud instance would immediately regenerate real data using the same pipeline.

## 📌 Project Overview
This project involves the deployment of a customized, interactive SSH honeypot (Cowrie) within an isolated AWS Virtual Private Cloud (VPC). The objective was to attract, log, and analyze real-world brute-force attacks and malware delivery attempts from automated botnets on the public internet.

## 🛠️ Technology Stack
- **Cloud Infrastructure:** AWS (EC2, VPC, Security Groups)
- **Operating System:** Ubuntu Linux 24.04 LTS
- **Honeypot Framework:** Cowrie (Python-based interactive shell environment)
- **Networking:** `iptables` for silent port forwarding (Port 22 → 2222)
- **Data Analysis:** Python (JSON parsing, data extraction)
- **AI-Assisted Analysis:** Anthropic Claude API for session intent classification

## 🏗️ Architecture & Configuration
To ensure maximum security and authentic data capture, the architecture was designed with the following parameters:

1. **Admin Isolation:** True administrative SSH access was migrated to a non-standard port (65222) and restricted via AWS Security Groups to accept connections only from a trusted IP address.
2. **The Trap:** Incoming traffic on the default SSH port (22) was silently routed to the Cowrie honeypot running in a restricted user environment.
3. **Deception:** The honeypot was configured with a simulated Debian filesystem and realistic hostnames to delay attacker detection and capture maximum payload commands.

## 📊 Threat Intelligence Analysis
A custom Python script (`analyze_threats.py`) parses the structured `cowrie.json` logs to extract Indicators of Compromise (IoCs).

### Top Attacker IP Addresses
*(updated as the honeypot accumulates more runtime)*

| IP Address | Attempts |
|---|---|
| `IP_ADDRESS` | `COUNT` |
| `IP_ADDRESS` | `COUNT` |

### Top Guessed Credentials
| Username / Password | Attempts |
|---|---|
| `root` / `password` | `COUNT` |
| `admin` / `123456` | `COUNT` |

## 🤖 AI-Assisted Threat Classification & Validation

Raw logs show *what* commands an attacker ran, but not *why* — whether it's a
scripted IoT botnet, a cryptominer dropper, or manual reconnaissance. To go
from raw data to actionable intelligence, `ai_threat_classifier.py` sends
each session's command sequence to Claude and asks for a short intent label.

**This is deliberately not a "trust the AI" pipeline.** Every AI
classification is independently checked against a small set of known
attack-signature keyword patterns (e.g. `busybox`/`tftp`/`.arm` binaries →
IoT botnet; `xmrig`/`stratum+tcp` → cryptominer; `wget`+`chmod +x`+execute →
payload dropper). When the AI's label and the signature match disagree, the
session is flagged for manual review rather than accepted automatically.

### Sample validation run (4 representative sessions)
```
Total sessions analyzed: 4
Signature/AI agreement:   3
Signature/AI disagreement: 1
No signature match:       0
```

**What the one disagreement taught me:** in the sample run, the AI labeled a
session as *"payload download and remote execution"* while the keyword
matcher flagged it more narrowly as *"cryptominer dropper"* — the AI wasn't
wrong, it was describing the general mechanism (download → chmod → execute)
rather than the specific payload family, since it has no way to know the
downloaded binary was `xmrig` without inspecting the file itself. That's a
real limitation worth knowing before trusting a model's classification in an
automated pipeline: **it reasons well over the command sequence, but has no
visibility into the actual payload contents**, so I keep the signature layer
as a mandatory cross-check rather than optional.

## 💡 Key Learnings
- Gained hands-on experience configuring AWS network boundaries and security groups.
- Deepened understanding of Linux user privileges, daemon processes, and `iptables` routing.
- Successfully automated the parsing of complex JSON security logs using Python.
- Learned to treat AI classification output as a *hypothesis to verify*, not
  a fact to trust — building an independent signature-based check surfaced a
  real blind spot (no payload-content visibility) rather than just taking
  the model's label at face value.

## 🚀 Running It
```bash
# Signature + live honeypot data
export ANTHROPIC_API_KEY=your_key
python3 ai_threat_classifier.py cowrie.json.log --out report.json

# No live data yet? Run the bundled demo sessions
python3 ai_threat_classifier.py --demo
```
