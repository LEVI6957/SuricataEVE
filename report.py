#!/usr/bin/env python3
"""
Auto Thesis Report Generator untuk SuricataEVE
Menghasilkan metrik akademis, visualisasi, dan rekaman audit untuk evaluasi IDS/IPS.
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
import statistics

try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    import pandas as pd
    import numpy as np
except ImportError:
    print("ERROR: Missing required libraries. Please run: pip install pandas matplotlib seaborn numpy")
    sys.exit(1)

# Config logging
os.makedirs("reports", exist_ok=True)
os.makedirs(os.path.join("dashboard", "static"), exist_ok=True)

logger = logging.getLogger("report")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
fh = logging.FileHandler(os.path.join("reports", "warnings.log"), mode='w')
formatter = logging.Formatter('%(levelname)s: %(message)s')
ch.setFormatter(formatter)
fh.setFormatter(formatter)
logger.addHandler(ch)
logger.addHandler(fh)

def parse_args():
    parser = argparse.ArgumentParser(description="SuricataEVE Auto Thesis Report Generator")
    parser.add_argument("--attackers-file", default="attackers.txt", help="Ground Truth file for attacker IPs")
    parser.add_argument("--normal-file", default="normal.txt", help="Ground Truth file for normal IPs")
    parser.add_argument("--eve-log", default=os.path.join("logs", "eve.json"), help="Path to Suricata eve.json")
    parser.add_argument("--blocked-log", default=os.path.join("auto_block", "blocked_ips.log"), help="Path to iptables blocked log")
    parser.add_argument("--metadata", default="attack_metadata.json", help="Path to attack metadata JSON")
    return parser.parse_args()

def load_ips(filepath):
    if not os.path.exists(filepath):
        logger.error(f"{filepath} not found. Please provide Ground Truth Dataset.")
        sys.exit(1)
    with open(filepath, 'r') as f:
        return set(line.strip() for line in f if line.strip())

def parse_iso_time(ts_str):
    # e.g., "2026-06-18T19:20:01.123456+0000" or "2026-06-18 19:20:01 UTC"
    try:
        if "UTC" in ts_str:
            ts_str = ts_str.replace(" UTC", "+0000")
            return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S%z")
        # Handle python pre-3.11 fromisoformat issues with 'Z'
        ts_str = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(ts_str)
    except Exception as e:
        logger.error(f"Failed to parse time {ts_str}: {e}")
        return None

def main():
    args = parse_args()
    
    # 1. Load Ground Truth
    attackers = load_ips(args.attackers_file)
    normals = load_ips(args.normal_file)
    
    # Load Metadata if exists
    metadata = {}
    if os.path.exists(args.metadata):
        with open(args.metadata, 'r') as f:
            metadata = json.load(f)
            
    # 2. Parse eve.json (Observed Dataset)
    detected_ips = set()
    first_alert_time = {}
    alert_signatures = {}
    total_alerts = 0
    
    if os.path.exists(args.eve_log):
        with open(args.eve_log, 'r') as f:
            for line in f:
                if not line.strip(): continue
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        total_alerts += 1
                        src_ip = event.get("src_ip")
                        ts = event.get("timestamp")
                        sig = event.get("alert", {}).get("signature", "Unknown")
                        sev = event.get("alert", {}).get("severity", "Unknown")
                        
                        if src_ip:
                            detected_ips.add(src_ip)
                            parsed_time = parse_iso_time(ts)
                            if src_ip not in first_alert_time or (parsed_time and first_alert_time[src_ip] > parsed_time):
                                first_alert_time[src_ip] = parsed_time
                                
                            sig_key = f"{sig} | {sev}"
                            alert_signatures[sig_key] = alert_signatures.get(sig_key, 0) + 1
                except json.JSONDecodeError:
                    continue
    else:
        logger.warning(f"{args.eve_log} not found. Ensure Suricata is running and logging.")

    # 3. Parse blocked_ips.log
    blocked_ips = set()
    block_times = {}
    if os.path.exists(args.blocked_log):
        with open(args.blocked_log, 'r') as f:
            for line in f:
                parts = line.strip().split(" | ")
                if len(parts) >= 3 and parts[1] == "BLOCKED":
                    ts_str = parts[0]
                    ip = parts[2]
                    blocked_ips.add(ip)
                    block_times[ip] = parse_iso_time(ts_str)

    # 4. Calculate TP, TN, FP, FN
    tp = len(detected_ips.intersection(attackers))
    fp = len(detected_ips.intersection(normals))
    fn = len(attackers - detected_ips)
    tn = len(normals - detected_ips)
    
    # Calculate Academic Metrics
    total_samples = tp + tn + fp + fn
    accuracy = (tp + tn) / total_samples if total_samples > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    detection_coverage = tp / len(attackers) if len(attackers) > 0 else 0

    # 5. Calculate Mitigation Metrics
    successfully_blocked_attackers = len(blocked_ips.intersection(attackers))
    detected_attackers = len(detected_ips.intersection(attackers))
    
    successful_mitigation_rate = successfully_blocked_attackers / detected_attackers if detected_attackers > 0 else 0
    failed_mitigation_count = len(detected_ips.intersection(attackers) - blocked_ips)
    
    # Log anomalies to warnings.log
    for ip in (detected_ips.intersection(attackers) - blocked_ips):
        logger.warning(f"IP {ip} detected but mitigation failed (Not blocked).")
    for ip in (blocked_ips - detected_ips):
        logger.warning(f"IP {ip} blocked but alert not found in eve.json.")

    # 6. Calculate Response Time
    latencies = []
    response_times_data = []
    for ip in blocked_ips.intersection(attackers):
        if ip in first_alert_time and ip in block_times:
            t1 = first_alert_time[ip]
            t2 = block_times[ip]
            if t1 and t2:
                diff = (t2 - t1).total_seconds()
                if diff < 0: diff = 0 # Clock skew fallback
                latencies.append(diff)
                response_times_data.append({"IP": ip, "Alert_Time": t1.isoformat(), "Block_Time": t2.isoformat(), "Latency_s": diff})

    min_rt = min(latencies) if latencies else 0
    max_rt = max(latencies) if latencies else 0
    mean_rt = statistics.mean(latencies) if latencies else 0
    median_rt = statistics.median(latencies) if latencies else 0
    std_rt = statistics.stdev(latencies) if len(latencies) > 1 else 0

    # 7. Generate CSV Reports
    metrics_data = [
        {"Metric": "TP", "Value": tp},
        {"Metric": "FP", "Value": fp},
        {"Metric": "TN", "Value": tn},
        {"Metric": "FN", "Value": fn},
        {"Metric": "Accuracy", "Value": f"{accuracy*100:.2f}%"},
        {"Metric": "Precision", "Value": f"{precision*100:.2f}%"},
        {"Metric": "Recall", "Value": f"{recall*100:.2f}%"},
        {"Metric": "F1-Score", "Value": f"{f1_score*100:.2f}%"},
        {"Metric": "False Positive Rate", "Value": f"{fpr*100:.2f}%"},
        {"Metric": "Detection Coverage", "Value": f"{detection_coverage*100:.2f}%"},
        {"Metric": "Successful Mitigation Rate", "Value": f"{successful_mitigation_rate*100:.2f}%"},
        {"Metric": "Failed Mitigation Count", "Value": failed_mitigation_count},
        {"Metric": "Min Response Time", "Value": f"{min_rt:.3f} s"},
        {"Metric": "Max Response Time", "Value": f"{max_rt:.3f} s"},
        {"Metric": "Mean Response Time", "Value": f"{mean_rt:.3f} s"},
        {"Metric": "Median Response Time", "Value": f"{median_rt:.3f} s"},
        {"Metric": "Std Dev Response Time", "Value": f"{std_rt:.3f} s"}
    ]
    pd.DataFrame(metrics_data).to_csv(os.path.join("reports", "metrics.csv"), index=False)

    attack_stats = []
    for sig_key, count in sorted(alert_signatures.items(), key=lambda x: x[1], reverse=True)[:10]:
        sig, sev = sig_key.split(" | ")
        attack_stats.append({"Signature": sig.strip(), "Severity": sev.strip(), "Count": count})
    pd.DataFrame(attack_stats).to_csv(os.path.join("reports", "attack_stats.csv"), index=False)
    pd.DataFrame(response_times_data).to_csv(os.path.join("reports", "response_times.csv"), index=False)

    # Test Config Snapshot
    config_snap = {
        "attackers_file": args.attackers_file,
        "normal_file": args.normal_file,
        "eve_log": args.eve_log,
        "blocked_log": args.blocked_log,
        "generated_at": datetime.now(timezone.utc).isoformat()
    }
    with open(os.path.join("reports", "test_config.json"), "w") as f:
        json.dump(config_snap, f, indent=2)

    # 8. Generate Visualizations
    static_dir = os.path.join("dashboard", "static")
    
    # A. Confusion Matrix
    cm = np.array([[tn, fp], [fn, tp]])
    plt.figure(figsize=(6, 4))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Normal', 'Attacker'], yticklabels=['Normal', 'Attacker'])
    plt.title('Confusion Matrix')
    plt.xlabel('Predicted Label (Observed Dataset)')
    plt.ylabel('True Label (Ground Truth)')
    plt.tight_layout()
    plt.savefig(os.path.join(static_dir, 'confusion_matrix.png'))
    plt.close()

    # B. Accuracy Chart
    plt.figure(figsize=(6, 4))
    sns.barplot(x=['Total Attackers', 'Detected (TP)', 'Missed (FN)'], y=[len(attackers), tp, fn], hue=['Total Attackers', 'Detected (TP)', 'Missed (FN)'], palette=['gray', 'green', 'red'], legend=False)
    plt.title('Detection Performance')
    plt.ylabel('Count')
    plt.tight_layout()
    plt.savefig(os.path.join(static_dir, 'accuracy_chart.png'))
    plt.close()

    # C. Mitigation Chart
    plt.figure(figsize=(6, 4))
    plt.pie([successfully_blocked_attackers, failed_mitigation_count], labels=['Blocked', 'Failed/Missed'], autopct='%1.1f%%', colors=['#2ecc71', '#e74c3c'], startangle=90)
    plt.title('Mitigation Effectiveness on Detected Attackers')
    plt.axis('equal')
    plt.savefig(os.path.join(static_dir, 'mitigation_chart.png'))
    plt.close()

    # D. Latency Chart
    plt.figure(figsize=(8, 4))
    if latencies:
        plt.plot(range(1, len(latencies)+1), latencies, marker='o', linestyle='-', color='b')
        plt.axhline(y=mean_rt, color='r', linestyle='--', label=f'Mean: {mean_rt:.3f}s')
        plt.title('Response Time per IP')
        plt.xlabel('Incident Sequence')
        plt.ylabel('Latency (Seconds)')
        plt.legend()
    else:
        plt.text(0.5, 0.5, 'No Latency Data', ha='center', va='center')
    plt.tight_layout()
    plt.savefig(os.path.join(static_dir, 'latency_chart.png'))
    plt.close()

    # 9. Generate HTML Summary
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SuricataEVE - Academic Thesis Report</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f8f9fa; color: #333; margin: 0; padding: 20px; }}
            .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); border-radius: 8px; }}
            h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
            h2 {{ color: #2980b9; margin-top: 30px; }}
            .grid {{ display: flex; flex-wrap: wrap; gap: 20px; margin-top: 20px; }}
            .card {{ flex: 1 1 calc(50% - 20px); background: #f1f2f6; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }}
            .card img {{ max-width: 100%; height: auto; border-radius: 4px; }}
            .highlight {{ font-size: 1.2em; font-weight: bold; color: #e74c3c; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #3498db; color: white; }}
            .interpretation {{ background-color: #e8f4f8; border-left: 4px solid #3498db; padding: 10px; margin-top: 10px; font-style: italic; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>SuricataEVE Evaluation Report</h1>
            <p>Generated at: <strong>{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</strong></p>
            
            <h2>1. Audit Trail & Metadata</h2>
            <table>
                <tr><th>Parameter</th><th>Value</th></tr>
                <tr><td>Test Date</td><td>{metadata.get('test_date', 'N/A')}</td></tr>
                <tr><td>Attack Type</td><td>{metadata.get('attack_type', 'N/A')}</td></tr>
                <tr><td>Target IP</td><td>{metadata.get('target_ip', 'N/A')}</td></tr>
                <tr><td>Suricata Version</td><td>{metadata.get('suricata_version', 'N/A')}</td></tr>
            </table>

            <h2>2. Academic Metrics Summary</h2>
            <div class="grid">
                <div class="card">
                    <h3>Detection Quality</h3>
                    <p>Detection Coverage: <span class="highlight">{detection_coverage*100:.2f}%</span></p>
                    <p>Precision: <strong>{precision*100:.2f}%</strong></p>
                    <p>Recall: <strong>{recall*100:.2f}%</strong></p>
                    <p>F1-Score: <strong>{f1_score*100:.2f}%</strong></p>
                    <p>False Positive Rate: <strong>{fpr*100:.2f}%</strong></p>
                    <div class="interpretation">
                        Sistem mencapai Detection Coverage sebesar {detection_coverage*100:.2f}% dengan F1-Score sebesar {f1_score*100:.2f}% berdasarkan Ground Truth Dataset.
                    </div>
                </div>
                <div class="card">
                    <h3>Mitigation Quality</h3>
                    <p>Successful Mitigation Rate: <span class="highlight">{successful_mitigation_rate*100:.2f}%</span></p>
                    <p>Failed Mitigation Count: <strong>{failed_mitigation_count}</strong></p>
                    <p>Avg Response Time: <strong>{mean_rt:.3f} s</strong></p>
                    <p>Std Dev Response Time: <strong>{std_rt:.3f} s</strong></p>
                    <div class="interpretation">
                        Tingkat keberhasilan pemblokiran (Successful Mitigation Rate) mencapai {successful_mitigation_rate*100:.2f}%, dengan rata-rata Response Time {mean_rt:.3f} detik.
                    </div>
                </div>
            </div>

            <h2>3. Dataset Overview</h2>
            <table>
                <tr><th>Category</th><th>Count</th></tr>
                <tr><td>Ground Truth Attackers</td><td>{len(attackers)}</td></tr>
                <tr><td>Ground Truth Normal Hosts</td><td>{len(normals)}</td></tr>
                <tr><td>Observed Alerts Total</td><td>{total_alerts}</td></tr>
                <tr><td>Unique Attackers Detected</td><td>{tp}</td></tr>
                <tr><td>Unique Attackers Blocked</td><td>{successfully_blocked_attackers}</td></tr>
            </table>

            <h2>4. Visualizations</h2>
            <div class="grid">
                <div class="card">
                    <h3>Confusion Matrix</h3>
                    <img src="confusion_matrix.png" alt="Confusion Matrix">
                </div>
                <div class="card">
                    <h3>Detection Performance</h3>
                    <img src="accuracy_chart.png" alt="Accuracy Chart">
                </div>
                <div class="card">
                    <h3>Mitigation Performance</h3>
                    <img src="mitigation_chart.png" alt="Mitigation Chart">
                </div>
                <div class="card">
                    <h3>Response Time (Latency)</h3>
                    <img src="latency_chart.png" alt="Latency Chart">
                </div>
            </div>
            
            <p style="text-align: center; margin-top: 40px; color: #7f8c8d; font-size: 0.9em;">SuricataEVE Auto Report Generator</p>
        </div>
    </body>
    </html>
    """
    with open(os.path.join(static_dir, "report_summary.html"), "w") as f:
        f.write(html_content)
        
    print(f"[OK] Report generated successfully!")
    print(f"  ➜ Metrics: reports/metrics.csv")
    print(f"  ➜ Visuals: dashboard/static/")
    print(f"  ➜ View HTML: http://[SERVER_IP]:8080/static/report_summary.html")

if __name__ == "__main__":
    main()
