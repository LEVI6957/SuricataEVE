import re

with open('dashboard/static/index.html', 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
skip = False
for line in lines:
    if '<div class="chart-container">' in line or 'chartCategory' in line or 'initCharts()' in line or 'refreshCharts()' in line:
        continue
    new_lines.append(line)

with open('dashboard/static/index.html', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)
