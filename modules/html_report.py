# modules/html_report.py
"""
SentinelX - HTML Dashboard Report Generator
Generates a responsive, dark-themed HTML incident response dashboard.
"""

import os
import json
from datetime import datetime

def generate_html_report(report_data, filename="report.html"):
    output_dir = "outputs"
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, filename)

    env_info = report_data.get("environment", {})
    env_label = env_info.get("label", "Unknown")
    platform_name = env_info.get("platform", "N/A")
    timestamp = report_data.get("timestamp", datetime.now().isoformat())

    # HTML Template with Hacker/Cyberpunk Dark Theme
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelX - Incident Response Dashboard</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --text-color: #c9d1d9;
            --text-muted: #8b949e;
            --accent-green: #238636;
            --accent-red: #da3633;
            --accent-yellow: #d29922;
            --accent-blue: #58a6ff;
            --font-code: 'Courier New', Courier, monospace;
        }}
        body {{
            background-color: var(--bg-color);
            color: var(--text-color);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        h1 {{
            margin: 0;
            color: var(--accent-blue);
            font-size: 24px;
        }}
        .badge {{
            background-color: #21262d;
            border: 1px solid var(--border-color);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 14px;
            font-family: var(--font-code);
        }}
        .card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        h2 {{
            margin-top: 0;
            font-size: 18px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
            color: var(--accent-blue);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            font-size: 14px;
        }}
        th, td {{
            text-align: left;
            padding: 10px;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background-color: #21262d;
            color: var(--text-muted);
        }}
        tr:hover {{
            background-color: rgba(255,255,255,0.02);
        }}
        .tag-red {{ color: var(--accent-red); font-weight: bold; }}
        .tag-green {{ color: var(--accent-green); font-weight: bold; }}
        .tag-yellow {{ color: var(--accent-yellow); font-weight: bold; }}
        footer {{
            text-align: center;
            margin-top: 40px;
            color: var(--text-muted);
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>🛡️ SentinelX Dashboard</h1>
                <p style="margin: 5px 0 0 0; color: var(--text-muted);">Enterprise Blue Team & Incident Response Suite</p>
            </div>
            <div>
                <span class="badge">Environment: {env_label}</span>
                <span class="badge">Timestamp: {timestamp}</span>
            </div>
        </header>

        <div class="card">
            <h2>System Overview</h2>
            <p><strong>Platform:</strong> {platform_name}</p>
            <p><strong>Is Android / Termux:</strong> {env_info.get('is_android', False)}</p>
            <p><strong>Is WSL / Kali:</strong> {env_info.get('is_wsl', False)}</p>
        </div>

        <div class="card">
            <h2>Network & Sockets Analysis</h2>
            <p>Generated report data loaded successfully. Check JSON export for deep analytical payload.</p>
        </div>

        <footer>
            Generated automatically by SentinelX Framework &bull; Offline Secure Report
        </footer>
    </div>
</body>
</html>
"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    print(f"[✓] HTML Dashboard successfully generated at: {filepath}")
    return filepath

