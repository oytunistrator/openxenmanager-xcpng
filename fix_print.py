import os
import re

def fix_print_in_file(filepath):
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    changed = False
    for i, line in enumerate(lines):
        line = line.rstrip('\n')
        # Match print followed by space and not already parenthesized
        match = re.match(r'(\s*)print\s+(.+)', line)
        if match and not line.strip().endswith(')'):
            indent = match.group(1)
            rest = match.group(2)
            lines[i] = indent + 'print(' + rest + ')\n'
            changed = True
    
    if changed:
        with open(filepath, 'w') as f:
            f.writelines(lines)
        print(f"Fixed {filepath}")

for root, dirs, files in os.walk('src'):
    for file in files:
        if file.endswith('.py'):
            fix_print_in_file(os.path.join(root, file))