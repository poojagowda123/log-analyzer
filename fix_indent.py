
import os

target_file = r"d:\LogAnalyzer1\LogAnalyzer\dashboard\app.py"

with open(target_file, "r", encoding="utf-8") as f:
    lines = f.readlines()

new_lines = []
for i, line in enumerate(lines):
    # Line 387 in 1-based index is index 386 in 0-based
    # We want to indent everything after the 'elif page == overview' line.
    # We double check if line 385 is the elif.
    if i >= 386: 
        if line.strip(): # Don't indent empty lines if not needed, but python usually fine with it
            new_lines.append("    " + line)
        else:
            new_lines.append(line)
    else:
        new_lines.append(line)

with open(target_file, "w", encoding="utf-8") as f:
    f.writelines(new_lines)

print(f"Fixed indentation for {len(lines) - 386} lines.")
