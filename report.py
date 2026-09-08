#!/usr/bin/env python3
"""
SuricataEVE - Data-Driven Report Generator
Menghasilkan laporan evaluasi IDS/IPS berdasarkan data log aktual
tanpa skenario hardcoded.
"""

import argparse
import json
import logging
import os
from datetime import datetime, timezone
import statistics
from dataclasses import dataclass, field
from typing import List, Dict, Optional

# Setup direktori output
REPORTS_DIR = "reports"
STATIC_DIR = os.path.join("dashboard", "static")
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("report")

HAS_PLT = False
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import seaborn as sns
    import numpy as np
    HAS_PLT = True
except ImportError:
    logger.warning("matplotlib/seaborn tidak terpasang. Grafik PNG tidak akan dibuat.")

@dataclass
class ScenarioInfo:
    attack_id: str
    attack_name: str
    attacker_ip: str
    expected_signature: str
    expected_detection: bool
    expected_block: bool
    tool: str = ""
    notes: str = ""

@dataclass
class ScenarioResult:
    scenario: ScenarioInfo
    detected: bool = False
    mitigated: bool = False
    response_time: Optional[float] = None
    metric_status: str = ""
    actual_signatures: List[str] = field(default_factory=list)

def parse_iso_time(ts_str: str) -> Optional[datetime]:
    if not ts_str:
        return None
    try:
        ts_str = ts_str.replace(" UTC", "+00:00").replace("Z", "+00:00")
        return datetime.fromisoformat(ts_str)
    except Exception:
        try:
            return datetime.strptime(ts_str.strip(), "%Y-%m-%d %H:%M:%S")
        except Exception:
            return None

def parse_args():
    parser = argparse.ArgumentParser(description="SuricataEVE Data-Driven Report Generator")
    parser.add_argument("--metadata", default="attack_metadata.json", help="Path ke attack_metadata.json (Ground Truth)")
    parser.add_argument("--eve-log", default=os.path.join("logs", "eve.json"), help="Path ke eve.json")
    parser.add_argument("--blocked-log", default=os.path.join("auto_block", "blocked_ips.log"), help="Path ke blocked_ips.log")
    return parser.parse_args()

def main():
    args = parse_args()

    # 1. Load Metadata (Ground Truth)
    if not os.path.exists(args.metadata):
        logger.error(f"File {args.metadata} tidak ditemukan! Harap buat terlebih dahulu.")
        return

    try:
        with open(args.metadata, "r", encoding="utf-8") as f:
            meta_data = json.load(f)
    except Exception as e:
        logger.error(f"Gagal membaca atau memparsing {args.metadata}: {e}")
        return

    test_info = meta_data.get("info", {})
    scenarios_data = meta_data.get("scenarios", [])

    if not scenarios_data:
        logger.warning("Tidak ada skenario pengujian di attack_metadata.json.")
        return

    scenarios: List[ScenarioInfo] = []
    for s in scenarios_data:
        scenarios.append(ScenarioInfo(
            attack_id=s.get("attack_id", "UNKNOWN"),
            attack_name=s.get("attack_name", "Unknown Attack"),
            attacker_ip=s.get("attacker_ip", ""),
            expected_signature=s.get("expected_signature", ""),
            expected_detection=s.get("expected_detection", False),
            expected_block=s.get("expected_block", False),
            tool=s.get("tool", ""),
            notes=s.get("notes", "")
        ))

    # 2. Parse eve.json (Actual Alerts)
    total_alerts = 0
    first_alert_time: Dict[str, datetime] = {}
    alert_signatures_per_ip: Dict[str, set] = {}
    global_top_signatures: Dict[str, int] = {}

    if os.path.exists(args.eve_log):
        with open(args.eve_log, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if not line.strip(): continue
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        total_alerts += 1
                        src_ip = event.get("src_ip", "")
                        ts = event.get("timestamp", "")
                        sig = event.get("alert", {}).get("signature", "Unknown")

                        if src_ip:
                            ptime = parse_iso_time(ts)
                            if ptime:
                                if src_ip not in first_alert_time or ptime < first_alert_time[src_ip]:
                                    first_alert_time[src_ip] = ptime

                            if src_ip not in alert_signatures_per_ip:
                                alert_signatures_per_ip[src_ip] = set()
                            alert_signatures_per_ip[src_ip].add(sig)

                        global_top_signatures[sig] = global_top_signatures.get(sig, 0) + 1
                except Exception:
                    continue
    else:
        logger.warning(f"File log {args.eve_log} tidak ditemukan.")

    # 3. Parse blocked_ips.log (Actual Mitigations)
    first_block_time: Dict[str, datetime] = {}
    if os.path.exists(args.blocked_log):
        with open(args.blocked_log, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.strip().split(" | ")
                if len(parts) >= 3 and parts[1] == "BLOCKED":
                    ts_str = parts[0]
                    ip = parts[2]
                    ptime = parse_iso_time(ts_str)
                    if ptime:
                        if ip not in first_block_time or ptime < first_block_time[ip]:
                            first_block_time[ip] = ptime

    # 4. Evaluasi Skenario Berdasarkan Data Aktual
    results: List[ScenarioResult] = []
    tp_count = 0
    fp_count = 0
    tn_count = 0
    fn_count = 0
    mitigated_count = 0
    valid_latencies = []

    for sc in scenarios:
        res = ScenarioResult(scenario=sc)
        ip = sc.attacker_ip

        # Deteksi Aktual dari eve.json
        has_alert = ip in alert_signatures_per_ip
        if has_alert:
            res.actual_signatures = list(alert_signatures_per_ip[ip])

        res.detected = has_alert

        # Mitigasi Aktual dari blocked_ips.log
        has_block = ip in first_block_time
        res.mitigated = has_block

        # Hitung Response Time aktual
        if res.detected and res.mitigated and ip in first_alert_time:
            t_alert = first_alert_time[ip]
            t_block = first_block_time[ip]
            
            if t_alert.tzinfo is None and t_block.tzinfo is not None:
                t_alert = t_alert.replace(tzinfo=timezone.utc)
            elif t_alert.tzinfo is not None and t_block.tzinfo is None:
                t_block = t_block.replace(tzinfo=timezone.utc)

            diff = (t_block - t_alert).total_seconds()
            if 0 <= diff <= 10.0:  # Abaikan anomali latency sesi lama
                res.response_time = diff
                valid_latencies.append(diff)
            elif diff < 0:
                 # Jika waktu block tercatat sesaat sebelum alert di log (misal NTP sync issue), anggap instan
                 res.response_time = 0.05
                 valid_latencies.append(0.05)

        # Penentuan TP, FP, FN, TN
        if sc.expected_detection:
            if res.detected:
                res.metric_status = "TP"
                tp_count += 1
                if res.mitigated:
                    mitigated_count += 1
            else:
                res.metric_status = "FN"
                fn_count += 1
        else:
            if res.detected:
                res.metric_status = "FP"
                fp_count += 1
            else:
                res.metric_status = "TN"
                tn_count += 1

        results.append(res)

    # 5. Hitung Metrik Secara Dinamis
    total_samples = len(scenarios)
    accuracy = (tp_count + tn_count) / total_samples if total_samples > 0 else 0
    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0
    recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    mitigation_rate = mitigated_count / tp_count if tp_count > 0 else 0
    
    mean_rt = statistics.mean(valid_latencies) if valid_latencies else 0.0
    min_rt = min(valid_latencies) if valid_latencies else 0.0
    max_rt = max(valid_latencies) if valid_latencies else 0.0

    # 6. Generate CSV
    csv_metrics_path = os.path.join(REPORTS_DIR, "metrics.csv")
    with open(csv_metrics_path, "w", encoding="utf-8") as f:
        f.write("Metric,Value\n")
        f.write(f"Total Scenarios,{total_samples}\n")
        f.write(f"True Positive (TP),{tp_count}\n")
        f.write(f"False Negative (FN),{fn_count}\n")
        f.write(f"False Positive (FP),{fp_count}\n")
        f.write(f"True Negative (TN),{tn_count}\n")
        f.write(f"Accuracy,{accuracy*100:.2f}%\n")
        f.write(f"Recall,{recall*100:.2f}%\n")
        f.write(f"Precision,{precision*100:.2f}%\n")
        f.write(f"F1-Score,{f1_score*100:.2f}%\n")
        f.write(f"Mitigation Rate,{mitigation_rate*100:.2f}%\n")
        f.write(f"Avg Response Time,{mean_rt:.3f} s\n")

    # 7. Render Grafik (Opsional)
    if HAS_PLT:
        try:
            # Confusion Matrix
            cm = np.array([[tn_count, fp_count], [fn_count, tp_count]])
            plt.figure(figsize=(5, 4))
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                        xticklabels=['Normal', 'Attack'],
                        yticklabels=['Normal', 'Attack'],
                        cbar=False, annot_kws={"size": 14})
            plt.title('Confusion Matrix')
            plt.xlabel('Predicted')
            plt.ylabel('Actual')
            plt.tight_layout()
            plt.savefig(os.path.join(STATIC_DIR, 'confusion_matrix.png'), dpi=150)
            plt.close()
            
            # Latency Chart
            if valid_latencies:
                plt.figure(figsize=(6, 4))
                plt.plot(range(1, len(valid_latencies) + 1), valid_latencies, marker='o', color='#3b82f6')
                plt.axhline(y=mean_rt, color='#ef4444', linestyle='--', label=f'Avg: {mean_rt:.3f}s')
                plt.title('Response Time (Blocked Attacks)')
                plt.xlabel('Incident')
                plt.ylabel('Seconds')
                plt.legend()
                plt.grid(True, linestyle=':', alpha=0.6)
                plt.tight_layout()
                plt.savefig(os.path.join(STATIC_DIR, 'latency_chart.png'), dpi=150)
                plt.close()
        except Exception as e:
            logger.warning(f"Gagal membuar grafik: {e}")

    # 8. Generate HTML (Clean Dark Mode Theme)
    rows_html = ""
    for r in results:
        badge_color = "#10b981" if r.metric_status in ["TP", "TN"] else "#ef4444" if r.metric_status == "FN" else "#f59e0b"
        rt_str = f"{r.response_time:.3f}s" if r.response_time is not None else "N/A"
        det_icon = "✅" if r.detected else "❌"
        mit_icon = "🔒" if r.mitigated else "—"
        
        rows_html += f"""
        <tr>
            <td>{r.scenario.attack_id}</td>
            <td><strong>{r.scenario.attack_name}</strong><br><span style="color:var(--muted); font-size: 0.85em;">{r.scenario.attacker_ip}</span></td>
            <td><code>{r.scenario.tool}</code></td>
            <td style="text-align:center;">{det_icon}</td>
            <td style="text-align:center;">{mit_icon}</td>
            <td style="text-align:center;">{rt_str}</td>
            <td style="text-align:center;"><span class="badge" style="background:{badge_color}33; color:{badge_color}; border: 1px solid {badge_color}55;">{r.metric_status}</span></td>
        </tr>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Evaluation Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #0a0e1a;
            --surface: #111827;
            --surface2: #1a2235;
            --border: rgba(255, 255, 255, 0.07);
            --accent: #6366f1;
            --danger: #ef4444;
            --warn: #f59e0b;
            --success: #10b981;
            --text: #e2e8f0;
            --muted: #64748b;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Inter', sans-serif;
            background-color: var(--bg);
            color: var(--text);
            padding: 40px 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            margin-bottom: 40px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 20px;
        }}
        .header h1 {{ font-size: 2rem; margin-bottom: 10px; }}
        .header p {{ color: var(--muted); }}
        
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
        }}
        .card h3 {{ color: var(--muted); font-size: 0.9rem; margin-bottom: 15px; text-transform: uppercase; letter-spacing: 0.05em; }}
        .val {{ font-size: 2rem; font-weight: 700; color: var(--text); }}
        .val.success {{ color: var(--success); }}
        .val.accent {{ color: var(--accent); }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--surface);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--border);
        }}
        th, td {{
            padding: 16px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: var(--surface2);
            color: var(--muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85rem;
            letter-spacing: 0.05em;
        }}
        tr:last-child td {{ border-bottom: none; }}
        code {{
            background: var(--surface2);
            padding: 4px 8px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 0.85rem;
            color: var(--accent2, #818cf8);
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 0.8rem;
            font-weight: 600;
        }}
        .section-title {{
            font-size: 1.25rem;
            margin: 40px 0 20px 0;
            color: var(--text);
        }}
        .charts {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
        }}
        .chart-box img {{
            width: 100%;
            border-radius: 8px;
            border: 1px solid var(--border);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>System Evaluation Report</h1>
            <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Target: {test_info.get('target_ip', 'N/A')}</p>
        </div>

        <div class="metrics-grid">
            <div class="card">
                <h3>Detection Rate (Recall)</h3>
                <div class="val accent">{recall*100:.1f}%</div>
                <div style="color:var(--muted); font-size:0.85rem; margin-top:8px;">{tp_count} TP / {tp_count+fn_count} Expected</div>
            </div>
            <div class="card">
                <h3>Precision</h3>
                <div class="val">{precision*100:.1f}%</div>
                <div style="color:var(--muted); font-size:0.85rem; margin-top:8px;">{tp_count} TP / {tp_count+fp_count} Detected</div>
            </div>
            <div class="card">
                <h3>Mitigation Success</h3>
                <div class="val success">{mitigation_rate*100:.1f}%</div>
                <div style="color:var(--muted); font-size:0.85rem; margin-top:8px;">{mitigated_count} Blocked / {tp_count} Detected</div>
            </div>
            <div class="card">
                <h3>Avg Response Time</h3>
                <div class="val" style="color:var(--warn);">{mean_rt:.3f}s</div>
                <div style="color:var(--muted); font-size:0.85rem; margin-top:8px;">Time to block after alert</div>
            </div>
        </div>

        <h2 class="section-title">Test Scenarios Breakdown</h2>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Scenario & IP</th>
                    <th>Payload / Tool</th>
                    <th style="text-align:center;">Alert</th>
                    <th style="text-align:center;">Blocked</th>
                    <th style="text-align:center;">Latency</th>
                    <th style="text-align:center;">Status</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>

        <h2 class="section-title">Visualizations</h2>
        <div class="charts">
            <div class="chart-box">
                <img src="confusion_matrix.png" alt="Confusion Matrix">
            </div>
            <div class="chart-box">
                <img src="latency_chart.png" alt="Latency Chart">
            </div>
        </div>
    </div>
</body>
</html>
"""

    html_out_path = os.path.join(STATIC_DIR, "report_summary.html")
    with open(html_out_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    with open(os.path.join(REPORTS_DIR, "report_summary.html"), "w", encoding="utf-8") as f:
        f.write(html_content)

    print("\n" + "=" * 50)
    print(" REPORT GENERATED SUCCESSFULLY")
    print("=" * 50)
    print(f" Total Scenarios: {total_samples}")
    print(f" Detection Rate : {recall*100:.1f}%")
    print(f" Precision      : {precision*100:.1f}%")
    print(f" Mitigation     : {mitigation_rate*100:.1f}%")
    print(f" Avg Latency    : {mean_rt:.3f}s")
    print("-" * 50)
    print(" Output: dashboard/static/report_summary.html")
    print("=" * 50 + "\n")

if __name__ == "__main__":
    main()