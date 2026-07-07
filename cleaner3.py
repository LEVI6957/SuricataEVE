import re

with open('dashboard/app.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if 'hourly_activity: dict = defaultdict(int)' in line or 'category_counts: dict = defaultdict(int)' in line:
        continue
    new_lines.append(line)

with open('dashboard/app.py', 'w', encoding='utf-8') as f:
    f.writelines(new_lines)
