#!/usr/bin/env python3
"""Package the verified app as a read-only drag-to-Applications disk image."""
from pathlib import Path
import hashlib
import plistlib
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / 'dist-native'
APP = DIST / 'Sang4MSilicon.app'


def run(*args):
    subprocess.run(args, check=True)


info = plistlib.loads((APP / 'Contents/Info.plist').read_bytes())
version = info['CFBundleShortVersionString']
image = DIST / f'Sang4MSilicon-{version}-mac-universal.dmg'
run('codesign', '--verify', '--deep', '--strict', '--all-architectures', str(APP))
with tempfile.TemporaryDirectory(prefix='connect-dmg-') as temporary:
    stage = Path(temporary) / 'contents'
    stage.mkdir()
    run('ditto', str(APP), str(stage / 'Sang4MSilicon.app'))
    (stage / 'Applications').symlink_to('/Applications')
    shutil.copy2(APP / 'Contents/Resources/Connect.icns', stage / '.VolumeIcon.icns')
    raw = Path(temporary) / 'Connect-writable.dmg'
    run('hdiutil', 'create', '-ov', '-volname', 'Sang4MSilicon', '-srcfolder', str(stage), '-fs', 'HFS+', '-format', 'UDRW', str(raw))
    writable = Path(temporary) / 'writable'
    writable.mkdir()
    run('hdiutil', 'attach', '-nobrowse', '-mountpoint', str(writable), str(raw))
    try:
        run('xcrun', 'SetFile', '-a', 'C', str(writable))
    finally:
        run('hdiutil', 'detach', str(writable))
    run('hdiutil', 'convert', str(raw), '-ov', '-format', 'UDZO', '-o', str(image))
    run('hdiutil', 'verify', str(image))
    mount = Path(temporary) / 'mounted'
    mount.mkdir()
    run('hdiutil', 'attach', '-readonly', '-nobrowse', '-mountpoint', str(mount), str(image))
    try:
        packaged = mount / 'Sang4MSilicon.app'
        if (mount / '.VolumeIcon.icns').read_bytes() != (APP / 'Contents/Resources/Connect.icns').read_bytes():
            raise SystemExit('Disk image volume icon mismatch')
        flags = subprocess.check_output(['xcrun', 'GetFileInfo', '-a', str(mount)], text=True).strip()
        if 'C' not in flags:
            raise SystemExit('Disk image custom icon flag missing')
        if plistlib.loads((packaged / 'Contents/Info.plist').read_bytes()) != info:
            raise SystemExit('Disk image application metadata mismatch')
        if (mount / 'Applications').readlink() != Path('/Applications'):
            raise SystemExit('Disk image Applications shortcut missing')
        run('codesign', '--verify', '--deep', '--strict', '--all-architectures', str(packaged))
        for relative in ['Contents/MacOS/Connect', 'Contents/Resources/bin/mchip-vpn-helper', 'Contents/Resources/bin/mchip-vpn-broker']:
            if hashlib.sha256((packaged / relative).read_bytes()).digest() != hashlib.sha256((APP / relative).read_bytes()).digest():
                raise SystemExit('Disk image executable mismatch: ' + relative)
    finally:
        run('hdiutil', 'detach', str(mount))
print('Read-only DMG mounted, application signatures and executable hashes verified:', image.name)
