#!/usr/bin/env python3
"""Publish renamed artifacts, promote the existing release and hide old previews."""
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
repo = os.environ['GITHUB_REPOSITORY']
sha = os.environ['GITHUB_SHA']
plan = json.loads((ROOT / 'scripts/release-plan.json').read_text())


def gh(*args):
    return subprocess.check_output(['gh', *args], text=True)


def release(item):
    value = json.loads(gh('api', f"repos/{repo}/releases/{item['id']}"))
    if value['tag_name'] != item['tag']:
        raise SystemExit('Release identity changed; refusing to modify')
    return value


current = release(plan['current'])
previous = [(item, release(item)) for item in plan['hide']]
assets = sorted((ROOT / 'release-assets').iterdir())
names = {p.name for p in assets}
required = {'Sang4MSilicon-0.5.0-beta.22-mac-universal.dmg', 'Sang4MSilicon-0.5.0-beta.22-mac-universal.zip', 'Sang4MSilicon-0.5.0-beta.22-source.zip', 'build-info.json', 'SHA256SUMS.txt'}
if not required.issubset(names):
    raise SystemExit('Required renamed assets missing')
gh('release', 'upload', current['tag_name'], '--repo', repo, '--clobber', *map(str, assets))
notes = ROOT / 'release-notes.md'
notes.write_text((ROOT / 'DIAGNOSTICS.md').read_text() + f'\n构建提交：[`{sha[:12]}`](https://github.com/{repo}/commit/{sha})\n')
gh('release', 'edit', current['tag_name'], '--repo', repo, '--draft=false', '--prerelease=false', '--latest', '--title', 'Sang4MSilicon · macOS Universal', '--notes-file', str(notes))
# New assets are uploaded before removing obsolete names from this release only.
for asset in current['assets']:
    if asset['name'].startswith('Connect-'):
        gh('release', 'delete-asset', current['tag_name'], asset['name'], '--repo', repo, '--yes')
for item, old in previous:
    if old['prerelease'] and not old['draft']:
        gh('api', '--method', 'PATCH', f"repos/{repo}/releases/{item['id']}", '-F', 'draft=true')
        print('Hidden preview:', item['tag'])
promoted = release(plan['current'])
if promoted['draft'] or promoted['prerelease']:
    raise SystemExit('Release promotion was not confirmed')
for item, _ in previous:
    if not release(item)['draft']:
        raise SystemExit('Old preview is still visible: ' + item['tag'])
print('Formal release and hidden previews verified:', promoted['html_url'])
