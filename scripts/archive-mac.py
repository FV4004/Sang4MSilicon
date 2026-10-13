"""Archive an assembled macOS app while preserving executable modes and symlinks."""
from pathlib import Path
import hashlib, os, stat, zipfile
root = Path(__file__).resolve().parents[1]
app = root / 'dist/M Chip VPN Login-darwin-arm64/M Chip VPN Login.app'
out = root / 'dist/MChipVPNLogin-0.3.0-beta.1-mac-arm64-unsigned.zip'
with zipfile.ZipFile(out, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
    for parent, dirs, files in os.walk(app, followlinks=False):
        for name in dirs + files:
            p = Path(parent) / name
            relative = str(p.relative_to(app.parent))
            if p.is_symlink():
                info = zipfile.ZipInfo(relative)
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(info, os.readlink(p).encode())
            elif p.is_file():
                z.write(p, relative)
            elif p.is_dir():
                z.write(p, relative + '/')
sha = hashlib.sha256(out.read_bytes()).hexdigest()
(root / 'dist/SHA256SUMS.txt').write_text(f'{sha}  {out.name}\n')
print(out)
print(f'SHA256 {sha}; bytes {out.stat().st_size}')
