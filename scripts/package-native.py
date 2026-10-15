#!/usr/bin/env python3
"""Build a Universal 2 SwiftUI app and the unchanged native VPN core."""
from pathlib import Path
import hashlib, json, os, plistlib, shutil, subprocess
ROOT = Path(__file__).resolve().parents[1]
PROFILE = os.environ.get('LAB_PROFILE', '')
if PROFILE != 'A': raise SystemExit('LAB_PROFILE must be A')
VERSION = '0.5.0-beta.21'
REFRESH_MODE = 'disabled' if PROFILE == 'A' else 'enabled'
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
    shutil.copy2(Path(path) / 'ConnectBroker', DIST / f'Broker-{arch}')
    run('go', 'build', '-ldflags', '-X main.sessionRefreshMode=' + REFRESH_MODE + ' -X main.labProfile=' + PROFILE, '-trimpath', '-o', str(DIST / f'helper-{arch}'), '.', cwd=ROOT / 'vpn-helper', env={**os.environ, 'GOOS': 'darwin', 'GOARCH': goarch, 'CGO_ENABLED': '0'})
run('lipo', '-create', str(DIST / 'Connect-arm64'), str(DIST / 'Connect-x86_64'), '-output', str(mac / 'Connect'))
# Sign each architecture independently before Apple's lipo combines them.
for arch in ['arm64', 'x86_64']:
    thin = DIST / f'helper-{arch}'
    if subprocess.run(['codesign', '--display', str(thin)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
        run('codesign', '--remove-signature', str(thin))
    run('codesign', '--force', '--sign', '-', '--identifier', 'dev.connectlab.mchip-vpn-helper', str(thin))
    run('codesign', '--verify', '--strict', '--verbose=2', str(thin))
run('lipo', '-create', str(DIST / 'helper-arm64'), str(DIST / 'helper-x86_64'), '-output', str(binaries / 'mchip-vpn-helper'))
run('lipo', '-create', str(DIST / 'Broker-arm64'), str(DIST / 'Broker-x86_64'), '-output', str(binaries / 'mchip-vpn-broker'))
# Use the approved PNG unchanged as the source for all standard macOS icon sizes.
iconset = DIST / 'Connect.iconset'
iconset.mkdir(exist_ok=True)
for size in [16, 32, 128, 256, 512]:
    for scale in [1, 2]:
        suffix = '@2x' if scale == 2 else ''
        run('sips', '-z', str(size * scale), str(size * scale), str(ROOT / 'assets/Connect.png'), '--out', str(iconset / f'icon_{size}x{size}{suffix}.png'))
run('iconutil', '-c', 'icns', str(iconset), '-o', str(resources / 'Connect.icns'))
# Decode the ICNS again: validate every standard size rather than just its filename.
checkset = DIST / 'IconCheck.iconset'
run('iconutil', '-c', 'iconset', str(resources / 'Connect.icns'), '-o', str(checkset))
for size in [16, 32, 128, 256, 512]:
    for scale in [1, 2]:
        suffix = '@2x' if scale == 2 else ''
        png = (checkset / f'icon_{size}x{size}{suffix}.png').read_bytes()
        if png[:8] != b'\x89PNG\r\n\x1a\n' or int.from_bytes(png[16:20], 'big') != size * scale or int.from_bytes(png[20:24], 'big') != size * scale:
            raise SystemExit('Invalid application icon size')
info = {'CFBundleIconFile': 'Connect.icns', 'CFBundleExecutable': 'Connect', 'CFBundleIdentifier': 'dev.connectlab.mchip-vpn.native.diag12', 'CFBundleName': 'Connect Diagnostics', 'CFBundleDisplayName': '连接你的网络 · 通道诊断', 'CFBundlePackageType': 'APPL', 'CFBundleShortVersionString': VERSION, 'CFBundleVersion': '5021', 'LSMinimumSystemVersion': '13.0', 'NSHighResolutionCapable': True, 'NSLocalNetworkUsageDescription': '用于连接你提供的 VPN 服务器并访问其下发的内网资源。', 'NSPrincipalClass': 'NSApplication', 'NSAppTransportSecurity': {'NSAllowsLocalNetworking': True}}
(APP / 'Contents/Info.plist').write_bytes(plistlib.dumps(info))
run('codesign', '--verify', '--strict', '--all-architectures', '--verbose=2', str(binaries / 'mchip-vpn-helper'))
run('codesign', '--force', '--sign', '-', str(binaries / 'mchip-vpn-broker'))
(binaries / 'mchip-vpn-broker.sha256').write_text(hashlib.sha256((binaries / 'mchip-vpn-broker').read_bytes()).hexdigest() + '\n')
(binaries / 'mchip-vpn-helper.sha256').write_text(hashlib.sha256((binaries / 'mchip-vpn-helper').read_bytes()).hexdigest() + '\n')
shutil.copy2(ROOT / 'LICENSE', resources / 'LICENSE')
shutil.copy2(ROOT / 'app/THIRD_PARTY_NOTICES.md', resources / 'THIRD_PARTY_NOTICES.md')
run('codesign', '--force', '--options', 'runtime', '--sign', '-', str(APP))
run('codesign', '--verify', '--deep', '--strict', '--all-architectures', '--verbose=2', str(APP))
for binary in [mac / 'Connect', binaries / 'mchip-vpn-helper', binaries / 'mchip-vpn-broker']:
    arches = set(subprocess.check_output(['lipo', '-archs', str(binary)], text=True).split())
    if arches != {'arm64', 'x86_64'}: raise SystemExit('Universal architecture check failed')
if any(resources.rglob('*.asar')) or any(resources.rglob('node_modules')): raise SystemExit('Unexpected Electron runtime')
(DIST / 'build-info.json').write_text(json.dumps({'version': VERSION, 'experimentalProfile': PROFILE, 'sessionUpdateMode': REFRESH_MODE, 'baseline': '0.5.0-beta.10', 'realGatewayTested': False, 'ciMacOS': '15', 'framework': 'SwiftUI/AppKit/WKWebView', 'architectures': ['arm64', 'x86_64'], 'minimumMacOS': '13.0', 'commit': os.getenv('GITHUB_SHA', ''), 'developerIdSigned': False, 'notarized': False, 'adHocSigned': True, 'helperSHA256': hashlib.sha256((binaries / 'mchip-vpn-helper').read_bytes()).hexdigest()}, indent=2))
print('Universal native application and helper verified')
