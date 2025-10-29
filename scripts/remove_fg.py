#!/usr/bin/env python3
"""
Remove hardcoded foreground attributes with value #000000008b8b from main_window.glade
Usage: python3 remove_fg.py
"""
import io
from pathlib import Path
p = Path(__file__).resolve().parents[1] / 'src' / 'OXM' / 'ui' / 'main_window.glade'
if not p.exists():
    print('File not found:', p)
    raise SystemExit(1)
text = p.read_text(encoding='utf-8')
old = '<attribute name="foreground" value="#000000008b8b"/>'
count = text.count(old)
if count == 0:
    print('No occurrences found')
else:
    bak = p.with_suffix('.glade.bak')
    bak.write_text(text, encoding='utf-8')
    newtext = text.replace(old, '')
    p.write_text(newtext, encoding='utf-8')
    print(f'Replaced {count} occurrences in {p}')
