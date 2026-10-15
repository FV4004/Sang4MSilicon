#!/usr/bin/env python3
"""Apply one checked-in beta.11 overlay to a fresh beta.10 checkout."""
from pathlib import Path
import json, shutil, sys
ROOT = Path(__file__).resolve().parents[1]
profile = sys.argv[1] if len(sys.argv) == 2 else ''
manifest = json.loads((ROOT / 'experiments/manifest.json').read_text())
if profile not in manifest:
    raise SystemExit('Usage: python3 scripts/activate-experiment.py A|B|C')
for name in manifest[profile]:
    relative = Path(name)
    if relative.is_absolute() or '..' in relative.parts:
        raise SystemExit('Unsafe overlay path')
    dest = ROOT / relative
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / 'experiments' / profile / relative, dest)
print(f'Activated experimental profile {profile}; start each profile from a fresh checkout')
