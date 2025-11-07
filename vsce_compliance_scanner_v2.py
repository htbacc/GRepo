#!/usr/bin/env python3
"""
VS Code Extension Compliance Scanner — FINAL
OpenBash Pentesting Tools / PentestGPT
Features:
  - Semgrep-based static checks (semgrep-vsce-rules.yml)
  - Publisher info from VS Marketplace
  - License analysis
  - Telemetry / Data-handling / RCE detection
  - Permissions & capabilities extraction
  - 1..10 safety score (10 safest)
  - Per-extension JSON, consolidated report.json
  - HTML dashboard (index.html)
  - Auto-block list CSV (blocklist.csv) for score <= 4

Usage:
  python3 vsce_compliance_scanner_final.py /path/to/unpacked_extensions /path/to/output_dir
Requirements:
  - Python 3.8+
  - semgrep in PATH (pip install semgrep)
  - requests (pip install requests)
"""
import os
import sys
import json
import subprocess
import shlex
import requests
import html
import shutil   # ✅ added this import
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

# ---- Args ----
if len(sys.argv) < 3:
    print("Usage: python3 vsce_compliance_scanner_final.py <extensions_dir> <output_dir>")
    sys.exit(1)

EXT_DIR = Path(sys.argv[1])
OUT_DIR = Path(sys.argv[2])
OUT_DIR.mkdir(parents=True, exist_ok=True)

SEMREG_CONFIG = Path(__file__).parent / "semgrep-vsce-rules.yml"

# ---- Helpers ----
def run_cmd(cmd: str, cwd: Path = None, timeout: int = 300):
    """Run shell command and return (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(cmd, shell=True, cwd=str(cwd) if cwd else None,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        return proc.returncode, proc.stdout.decode(errors="ignore"), proc.stderr.decode(errors="ignore")
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"

def has_cmd(name: str) -> bool:
    """Check if a command exists in PATH."""
    return shutil.which(name) is not None

# ---- Marketplace publisher info ----
def get_publisher_info(publisher: str) -> Dict[str, Any]:
    """Query VS Marketplace for basic publisher info. Best-effort, non-blocking."""
    if not publisher:
        return {"verified": False, "installs": 0, "displayName": publisher or "unknown"}
    try:
        url = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json;api-version=3.0-preview.1"
        }
        payload = {
            "filters": [{"criteria": [{"filterType": 7, "value": publisher}]}],
            "flags": 131
        }
        r = requests.post(url, headers=headers, json=payload, timeout=10)
        r.raise_for_status()
        data = r.json()
        if data.get("results"):
            exts = data["results"][0].get("extensions", [])
            if exts:
                ext0 = exts[0]
                pub = ext0.get("publisher", {})
                verified = pub.get("isVerified", False)
                # statistic extraction fallback
                installs = 0
                for stat in ext0.get("statistics", []) or []:
                    # look for installs statistic type
                    try:
                        installs = int(stat.get("value", installs))
                        break
                    except:
                        pass
                return {
                    "verified": verified,
                    "installs": installs,
                    "displayName": pub.get("displayName", publisher)
                }
        return {"verified": False, "installs": 0, "displayName": publisher}
    except Exception as e:
        return {"verified": False, "installs": 0, "displayName": publisher, "error": str(e)}

# ---- License analysis ----
def analyze_license(lic, folder_path=None) -> (str, str, int):
    """
    Return (license_str, reason, license_score 1..10).
    Reads license files (LICENSE, LICENSE.txt, LICENSE.md, etc.) and detects type by content.
    """

    license_files = ["LICENSE", "LICENSE.txt", "LICENSE.md", "license.txt", "license"]
    detected_license = None
    reason = ""
    score = 5  # neutral default

    # --- STEP 1: locate and read license file ---
    license_path = None
    if folder_path:
        for name in license_files:
            path = folder_path / name
            if path.exists():
                license_path = path
                break

    license_text = ""
    if license_path:
        try:
            license_text = license_path.read_text(errors="ignore").lower()
        except Exception as e:
            return ("Unreadable", f"Error reading license file: {e}", 4)

    # --- STEP 2: detect license by content ---
    if license_text:
        if "permission is hereby granted, free of charge" in license_text:
            detected_license = "MIT"
            reason = "MIT license detected by content"
            score = 10
        elif "apache license" in license_text and "version 2" in license_text:
            detected_license = "Apache 2.0"
            reason = "Apache License 2.0 detected by content"
            score = 10
        elif "redistribution and use in source and binary forms" in license_text and "bsd" in license_text:
            detected_license = "BSD"
            reason = "BSD-style license detected by content"
            score = 9
        elif "isc license" in license_text or "the isc license" in license_text:
            detected_license = "ISC"
            reason = "ISC license detected by content"
            score = 9
        elif "gnu general public license" in license_text:
            detected_license = "GPL"
            reason = "GPL-family license detected by content"
            score = 6
        elif "affero general public license" in license_text:
            detected_license = "AGPL"
            reason = "AGPL license detected by content"
            score = 5
        else:
            detected_license = "Custom"
            reason = "Custom or unknown license file"
            score = 7

        return (detected_license, reason, score)

    # --- STEP 3: fallback to package.json 'license' field ---
    if not lic:
        if license_path:
            return ("Custom", "License file found but unreadable", 6)
        return ("Missing", "No license found", 2)

    s = str(lic).lower()
    if "mit" in s or "apache" in s or "bsd" in s or "isc" in s:
        return (str(lic), "Permissive license by declaration", 10)
    if "gpl" in s or "agpl" in s or "lgpl" in s:
        return (str(lic), "Copyleft license (GPL-family)", 6)
    if "proprietary" in s or "closed" in s:
        return (str(lic), "Proprietary license – review required", 4)

    # fallback if not detected
    return (str(lic), "Unknown license", 5)


# ---- Semgrep scanning ----
def semgrep_scan(target: Path):
    """Run semgrep with configured ruleset. Returns list of findings (Semgrep JSON 'results')."""
    cmd = f"semgrep --quiet --json --config {shlex.quote(str(SEMREG_CONFIG))} {shlex.quote(str(target))}"
    rc, out, err = run_cmd(cmd)
    if not out:
        # semgrep may return nothing on error; include stderr as fallback
        return {"error": err.strip()[:200], "results": []}
    try:
        parsed = json.loads(out)
        results = parsed.get("results", [])
        return {"error": None, "results": results}
    except Exception as e:
        return {"error": f"semgrep parse error: {e}", "raw": out, "results": []}

# ---- Categorize semgrep results into telemetry, data-handling, rce, network, fs ----
def categorize_findings(results):
    telemetry = []
    data_handling = []
    rce = []
    network = []
    filesystem = []
    other = []
    for r in results:
        # semgrep result structure: 'check_id' or 'rule_id' plus 'extra' -> 'message'
        rid = r.get("check_id") or r.get("rule_id") or r.get("check_id") or ""
        message = (r.get("extra", {}) or {}).get("message", "") or r.get("msg", "") or ""
        # simple heuristics on id/message
        lowmsg = message.lower() + " " + rid.lower()
        if "telemetry" in lowmsg or "env.machineid" in lowmsg or "sessionid" in lowmsg or "appinsights" in lowmsg:
            telemetry.append(message or rid)
        if "data upload" in lowmsg or "data transfer" in lowmsg or "fetch" in lowmsg or "post(" in lowmsg:
            data_handling.append(message or rid)
        if "eval" in lowmsg or "child_process" in lowmsg or "vm" in lowmsg or "spawn(" in lowmsg:
            rce.append(message or rid)
        if "http" in lowmsg or "axios" in lowmsg or "fetch" in lowmsg or "ws" in lowmsg:
            network.append(message or rid)
        if "fs" in lowmsg or "filesystem" in lowmsg or "~/.ssh" in lowmsg or "private_key" in lowmsg:
            filesystem.append(message or rid)
        else:
            other.append(message or rid)
    return {
        "telemetry": telemetry,
        "data_handling": data_handling,
        "rce": rce,
        "network": network,
        "filesystem": filesystem,
        "other": other
    }

# ---- Capabilities extraction ----
def extract_capabilities_from_pkg(pkg: dict) -> str:
    caps = []
    for k in ("activationEvents", "capabilities", "contributes", "main", "browser"):
        if k in pkg:
            # for activationEvents show count maybe
            if k == "activationEvents" and isinstance(pkg[k], list):
                caps.append(f"activationEvents({len(pkg[k])})")
            else:
                caps.append(k)
    return ", ".join(caps) if caps else "None"

# ---- GDPR scoring ----
def gdpr_assess(categories) -> (str, str, int):
    flags = []
    if categories["telemetry"]:
        flags.append("telemetry")
    if categories["data_handling"]:
        flags.append("data_transfer")
    if flags:
        return ("REVIEW", f"Flags: {', '.join(flags)}", 5)
    return ("PASS", "No telemetry/data-transfer detected", 10)

# ---- Final score calculation (1..10) ----
def compute_score(license_score: int, gdpr_score: int, verified_pub: bool, semgrep_count: int, rce_count: int) -> int:
    base = (license_score + gdpr_score) / 2.0
    if not verified_pub:
        base -= 2
    # semgrep findings penalty
    if semgrep_count > 10:
        base -= 3
    elif semgrep_count > 3:
        base -= 1
    # rce penalty
    if rce_count > 0:
        base -= 3
    # clamp to 1..10
    sc = round(max(1, min(10, base)))
    return int(sc)

# ---- Main loop ----
reports = []
global_errors = []
for sub in sorted(EXT_DIR.iterdir()):
    if not sub.is_dir():
        continue
    pkg_path = sub / "package.json"
    if not pkg_path.exists():
        # skip folders without package.json (not an extension)
        continue

    ext_name = sub.name
    print(f"[+] Processing {ext_name}")
    try:
        pkg = json.loads(pkg_path.read_text(encoding="utf-8", errors="ignore"))
    except Exception as e:
        global_errors.append({"extension": ext_name, "error": f"package.json read error: {e}"})
        continue

    # gather basic fields
    ext_display_name = pkg.get("name") or ext_name
    publisher_field = pkg.get("publisher") or pkg.get("author") or "unknown"

    # publisher info
    pubinfo = get_publisher_info(publisher_field)

    # license analysis
    #license_val, license_reason, license_score = analyze_license(pkg.get("license") or pkg.get("licenses"))
    license_val, license_reason, license_score = analyze_license(pkg.get("license") or pkg.get("licenses"), sub)

    # semgrep scan
    sem = semgrep_scan(sub)
    sem_results = sem.get("results", []) if isinstance(sem, dict) else []
    sem_err = sem.get("error") if isinstance(sem, dict) else None

    # categorize
    cats = categorize_findings(sem_results)

    # capabilities
    capabilities = extract_capabilities_from_pkg(pkg)

    # gdpr assessment
    gdpr_status, gdpr_reason, gdpr_score = gdpr_assess(cats)

    # counts
    semgrep_count = len(sem_results)
    rce_count = len(cats.get("rce", []))

    # final score
    verified = bool(pubinfo.get("verified"))
    final_score = compute_score(license_score, gdpr_score, verified, semgrep_count, rce_count)

    # assemble reasons
    reasons = []
    reasons.append(license_reason)
    reasons.append(gdpr_reason)
    if not verified:
        reasons.append("Unverified publisher")
    if semgrep_count:
        reasons.append(f"{semgrep_count} semgrep findings")
    if rce_count:
        reasons.append(f"{rce_count} RCE-like findings")
    if sem_err:
        reasons.append(f"semgrep error: {sem_err}")

    # prepare per-extension report
    rep = {
        "extension_dir": str(sub),
        "extension_name": ext_display_name,
        "folder_name": ext_name,
        "publisher_field": publisher_field,
        "publisher_info": pubinfo,
        "license": license_val,
        "license_reason": license_reason,
        "capabilities": capabilities,
        "semgrep_findings_count": semgrep_count,
        "semgrep_findings": sem_results,
        "categories": cats,
        "gdpr_status": gdpr_status,
        "gdpr_reason": gdpr_reason,
        "final_score": final_score,
        "reason": "; ".join(reasons),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    # write per-extension JSON
    ext_out_dir = OUT_DIR / ext_name
    ext_out_dir.mkdir(parents=True, exist_ok=True)
    with open(ext_out_dir / "report.json", "w", encoding="utf-8") as f:
        json.dump(rep, f, indent=2)

    reports.append(rep)

# ---- Consolidated outputs ----
# write global report.json
global_report = {
    "generated_at": datetime.utcnow().isoformat() + "Z",
    "extensions_scanned": len(reports),
    "reports": reports
}
with open(OUT_DIR / "report.json", "w", encoding="utf-8") as gf:
    json.dump(global_report, gf, indent=2)

# write blocklist.csv (score <= 4)
import csv
blocklist_path = OUT_DIR / "blocklist.csv"
with open(blocklist_path, "w", newline="", encoding="utf-8") as bf:
    w = csv.writer(bf)
    w.writerow(["extension_name", "folder_name", "publisher", "final_score", "reason"])
    for r in reports:
        if r["final_score"] <= 4:
            w.writerow([r["extension_name"], r["folder_name"], r["publisher_field"], r["final_score"], r["reason"]])

# ---- HTML Dashboard ----
index = OUT_DIR / "index.html"
with open(index, "w", encoding="utf-8") as h:
    h.write("<!doctype html>\n<html><head><meta charset='utf-8'><title>VSCode Extensions Compliance Dashboard</title>\n")
    h.write("<style>body{font-family:Arial,Helvetica,sans-serif;margin:20px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px}th{background:#f2f2f2} .good{background:#e6ffed} .warn{background:#fff6e6} .bad{background:#ffe6e6} pre{white-space:pre-wrap;word-break:break-word}</style>\n")
    h.write("</head><body>\n")
    h.write(f"<h2>VSCode Extension Compliance Dashboard — {html.escape(datetime.utcnow().isoformat()+'Z')}</h2>\n")
    h.write(f"<p>Scanned {len(reports)} extensions. <a href='report.json'>Download JSON report</a> • <a href='blocklist.csv'>Blocklist CSV</a></p>\n")
    h.write("<table><thead><tr><th>Extension</th><th>Publisher</th><th>Verified</th><th>License</th><th>GDPR</th><th>Telemetry</th><th>Data Handling</th><th>RCE Risk</th><th>Capabilities</th><th>Score</th><th>Reason</th><th>Report</th></tr></thead><tbody>\n")
    for r in sorted(reports, key=lambda x: x["final_score"], reverse=True):
        score = r["final_score"]
        cls = "good" if score >= 8 else "bad" if score <= 4 else "warn"
        telemetry = ", ".join(r["categories"].get("telemetry") or []) or "None"
        datah = ", ".join(r["categories"].get("data_handling") or []) or "None"
        rce = "Yes" if len(r["categories"].get("rce") or []) > 0 else "No"
        pub = r["publisher_info"].get("displayName") if isinstance(r.get("publisher_info"), dict) else r.get("publisher_field")
        verified = "Yes" if r["publisher_info"].get("verified") else "No"
        h.write(f"<tr class='{cls}'>")
        h.write(f"<td>{html.escape(r['extension_name'])}</td>")
        h.write(f"<td>{html.escape(str(pub))}</td>")
        h.write(f"<td>{verified}</td>")
        h.write(f"<td>{html.escape(str(r['license']))}</td>")
        h.write(f"<td>{html.escape(r['gdpr_status'])}</td>")
        h.write(f"<td>{html.escape(telemetry)}</td>")
        h.write(f"<td>{html.escape(datah)}</td>")
        h.write(f"<td>{html.escape(rce)}</td>")
        h.write(f"<td>{html.escape(r['capabilities'])}</td>")
        h.write(f"<td>{score}</td>")
        h.write(f"<td>{html.escape(r['reason'])}</td>")
        h.write(f"<td><a href='{html.escape(r['folder_name'])}/report.json' target='_blank'>report.json</a></td>")
        h.write("</tr>\n")
    h.write("</tbody></table>\n")
    h.write("<h3>Notes</h3>\n")
    h.write("<ul><li>Score: 10 = safest; 1 = highest risk. Scores are heuristic. Manual review required for any non-10.</li>\n")
    h.write("<li>RCE Risk flagged when semgrep rules detect eval/child_process/vm/dynamic-require patterns — inspect each match.</li>\n")
    h.write("<li>Telemetry/data handling flags indicate potential personal data transfer — required GDPR review if present.</li>\n")
    h.write("</ul>\n")
    h.write("</body></html>\n")

print(f"[+] Done. Outputs in: {OUT_DIR}")
print(f"    - HTML dashboard: {index}")
print(f"    - Consolidated JSON: {OUT_DIR / 'report.json'}")
print(f"    - Blocklist CSV (score <=4): {blocklist_path}")

