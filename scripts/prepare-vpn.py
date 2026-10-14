#!/usr/bin/env python3
"""Fetch a fixed upstream protocol implementation and apply our documented patches."""
from pathlib import Path
import hashlib, shutil, tarfile, urllib.request
ROOT = Path(__file__).resolve().parents[1]
REV = 'c19eb4ed34b9cf6e8e8ea3315fe9973c8411eb63'
SHA = 'd0f48689be9a63432768f8e228920cfc7371b939281123628a91e583bc847798'
build = ROOT / '.build'
build.mkdir(exist_ok=True)
archive = build / 'upstream.tar.gz'
if not archive.exists():
    urllib.request.urlretrieve(f'https://codeload.github.com/Mythologyli/zju-connect/tar.gz/{REV}', archive)
if hashlib.sha256(archive.read_bytes()).hexdigest() != SHA:
    raise SystemExit('Upstream source checksum mismatch')
dest = build / 'zju-connect'
if dest.exists(): shutil.rmtree(dest)
with tarfile.open(archive) as tar:
    for member in tar.getmembers():
        if member.issym() or member.islnk() or not (build / member.name).resolve().is_relative_to(build.resolve()):
            raise SystemExit('Unsafe source archive member')
    tar.extractall(build)
(build / f'zju-connect-{REV}').rename(dest)
compress_archive = build / 'compress.tar.gz'
if not compress_archive.exists():
    urllib.request.urlretrieve('https://codeload.github.com/klauspost/compress/tar.gz/refs/tags/v1.18.6', compress_archive)
if hashlib.sha256(compress_archive.read_bytes()).hexdigest() != 'cd94476767c7928b995a77167aa37b0920c7db74d5a4eafd3a1a4a7055e74785':
    raise SystemExit('Compression source checksum mismatch')
compress_dest = build / 'compress-1.18.6'
if compress_dest.exists(): shutil.rmtree(compress_dest)
with tarfile.open(compress_archive) as tar:
    for member in tar.getmembers():
        if member.issym() or member.islnk() or not (build / member.name).resolve().is_relative_to(build.resolve()):
            raise SystemExit('Unsafe compression source member')
    tar.extractall(build)
with (dest / 'go.mod').open('a') as f:
    f.write('\nreplace github.com/klauspost/compress => ../compress-1.18.6\n')
# Preserve certificate checking; do not inherit upstream's blanket skip-verify.
for name in ['client.go','request.go','protocol.go']:
    p = dest / 'client/easyconnect' / name
    s = p.read_text()
    if 'InsecureSkipVerify: true' not in s:
        raise SystemExit(f'Expected upstream TLS setting missing: {name}')
    s = s.replace('InsecureSkipVerify: true', 'ServerName: mchipServerName(c.server), InsecureSkipVerify: false')
    if name == 'request.go':
        needle = 'c.token = (*[48]byte)([]byte(sessionID[:31] + "\\x00" + c.twfID))'
        if needle not in s: raise SystemExit('Expected token construction missing')
        s = s.replace(needle, 'if len(sessionID) < 31 || len(c.twfID) != 16 { return errors.New("unsupported EasyConnect session format") }\n\t' + needle)
        s = s.replace('if reply[0] != 0x00 {', 'if n < 8 || reply[0] != 0x00 {')
    p.write_text(s)
(dest / 'client/easyconnect/mchip_tls.go').write_text('''// Modified for M Chip VPN, 2026-10-13; AGPL-3.0.
package easyconnect
import "net"
func mchipServerName(server string) string {
 host, _, err := net.SplitHostPort(server)
 if err != nil { return server }
 return host
}
''')
# Supply unchanged upstream license and source to recipients of the helper.
shutil.copyfile(dest / 'LICENSE', ROOT / 'LICENSE')
shutil.copyfile(dest / 'LICENSE', ROOT / 'app/LICENSE')
print(f'Prepared zju-connect {REV}; TLS verification and session bounds patches applied')
# Reproducible protocol/lifecycle fixes, included in the published source archive.
import runpy
runpy.run_path(str(ROOT / 'vpn-patches/patch.py'))['apply'](dest, ROOT / 'vpn-patches')

shutil.copyfile(ROOT / "vpn-patches/mchip_control_diagnostic.go", dest / "client/easyconnect/mchip_control_diagnostic.go")

runpy.run_path(str(ROOT / "vpn-patches/session_refresh_patch.py"))["apply"](dest)
shutil.copyfile(ROOT / "vpn-patches/mchip_session_refresh_test.go", dest / "client/easyconnect/mchip_session_refresh_test.go")
