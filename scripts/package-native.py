#!/usr/bin/env python3
"""Build a Universal 2 SwiftUI app and the unchanged native VPN core."""
from pathlib import Path
import hashlib, json, os, plistlib, shutil, subprocess
ROOT = Path(__file__).resolve().parents[1]
VERSION = '0.5.0-beta.1'
DIST = ROOT / 'dist-native'
APP = DIST / 'Connect.app'
def run(*args, cwd=ROOT, env=None):
    subprocess.run(args, cwd=cwd, env=env, check=True)
if APP.exists(): shutil.rmtree(APP)
mac = APP / 'Contents/MacOS'; resources = APP / 'Contents/Resources'; binaries = resources / 'bin'
mac.mkdir(parents=True); binaries.mkdir(parents=True)
for arch, goarch in [('arm64', 'arm64'), ('x86_64', 'amd64')]:
    run('swift', 'build', '-c', 'release', '--arch', arch, cwd=ROOT / 'native')
    path = subprocess.check_output(['swift', 'build', '-c', 'release', '--arch', arch, '--show-bin-path'], cwd=ROOT / 'native', text=True).strip()
    shutil.copy2(Path(path) / 'ConnectApp', DIST / f'Connect-{arch}')
    run('go', 'build', '-trimpath', '-o', str(DIST / f'helper-{arch}'), '.', cwd=ROOT / 'vpn-helper', env={**os.environ, 'GOOS': 'darwin', 'GOARCH': goarch, 'CGO_ENABLED': '0'})
run('lipo', '-create', str(DIST / 'Connect-arm64'), str(DIST / 'Connect-x86_64'), '-output', str(mac / 'Connect'))
run('lipo', '-create', str(DIST / 'helper-arm64'), str(DIST / 'helper-x86_64'), '-output', str(binaries / 'mchip-vpn-helper'))
info = {'CFBundleExecutable': 'Connect', 'CFBundleIdentifier': 'dev.connectlab.mchip-vpn.native', 'CFBundleName': 'Connect', 'CFBundleDisplayName': '连接你的网络', 'CFBundlePackageType': 'APPL', 'CFBundleShortVersionString': VERSION, 'CFBundleVersion': '5001', 'LSMinimumSystemVersion': '13.0', 'NSHighResolutionCapable': True, 'NSPrincipalClass': 'NSApplication', 'NSAppTransportSecurity': {'NSAllowsLocalNetworking': True}}
(APP / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
run('codesign', '--force', '--sign', '-', str(binaries / 'mchip-vpn-helper'))
(binaries / 'mchip-vpn-helper.sha256').write_text(hashlib.sha256((binaries / 'mchip-vpn-helper').read_bytes()).hexdigest() + '\n')
shutil.copy2(ROOT / 'LICENSE', resources / 'LICENSE')
shutil.copy2(ROOT / 'app/THIRD_PARTY_NOTICES.md', resources / 'THIRD_PARTY_NOTICES.md')
run('codesign', '--force', '--sign', '-', str(APP))
run('codesign', '--verify', '--deep', '--strict', str(APP))
for binary in [mac / 'Connect', binaries / 'mchip-vpn-helper']:
    arches = set(subprocess.check_output(['lipo', '-archs', str(binary)], text=True).split())
    if arches != {'arm64', 'x86_64'}: raise SystemExit('Universal architecture check failed')
if any(resources.rglob('*.asar')) or any(resources.rglob('node_modules')): raise SystemExit('Unexpected Electron runtime')
(DIST / 'build-info.json').write_text(json.dumps({'version': VERSION, 'framework': 'SwiftUI/AppKit/WKWebView', 'architectures': ['arm64', 'x86_64'], 'minimumMacOS': '13.0', 'commit': os.getenv('GITHUB_SHA', ''), 'developerIdSigned': False, 'notarized': False, 'adHocSigned': True, 'helperSHA256': hashlib.sha256((binaries / 'mchip-vpn-helper').read_bytes()).hexdigest()}, indent=2))
print('Universal native application and helper verified')
