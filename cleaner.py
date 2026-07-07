import re

# Clean index.html
with open('dashboard/static/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# Remove chart CDN
content = re.sub(r'<script src="https://cdn\.jsdelivr\.net/npm/chart\.js.*?></script>\n', '', content)
# Remove chart CSS
content = re.sub(r'/\*.*?Server IP Badge.*?\*/.*?\.chart-empty.*?}', '', content, flags=re.DOTALL)
# Remove server ip badge from header
content = re.sub(r'<div class="server-ip-badge".*?</div>\n', '', content)
# Remove chart HTML
content = re.sub(r'<!-- Chart Row -->.*?</div>\s*</div>\s*</div>', '', content, flags=re.DOTALL)
# Remove chart JS variables
content = re.sub(r'let chartHourly = null;\n\s*let chartCategory = null;\n', '', content)
# Remove Server IP and Chart JS functions
content = re.sub(r'// ── Server IP ──.*?// ── Init ──', '// ── Init ──', content, flags=re.DOTALL)
# Remove chart init from initApp
content = re.sub(r'loadServerInfo\(\);\n\s*initCharts\(\);\n\s*refreshCharts\(\);\n', '', content)
content = re.sub(r'window\.chartInterval = setInterval\(refreshCharts, 10000\);\n', '', content)

with open('dashboard/static/index.html', 'w', encoding='utf-8') as f:
    f.write(content)

# Clean app.py
with open('dashboard/app.py', 'r', encoding='utf-8') as f:
    app_content = f.read()

# Remove data dicts
app_content = re.sub(r'# Data untuk grafik:.*?category_counts.*?int\)\n', '', app_content, flags=re.DOTALL)
# Remove update graph logic
app_content = re.sub(r'# Update data grafik.*?category_counts\[cat_key\] \+= 1\n', '', app_content, flags=re.DOTALL)
# Remove endpoints
app_content = re.sub(r'@app\.get\("/api/chart-data"\).*?return \{"server_ip": server_ip, "port": 8080\}\n', '', app_content, flags=re.DOTALL)

with open('dashboard/app.py', 'w', encoding='utf-8') as f:
    f.write(app_content)
