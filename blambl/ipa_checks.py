"""Shared fail-closed IPA checks for the server and the macOS build."""
import hashlib
import plistlib
import re
import struct
import zipfile


def supported_versions(readme):
    lines = [s for s in readme.splitlines() if 'Tested on versions' in s]
    if len(lines) != 1:
        raise ValueError('README stable release nemá jednoznačný seznam Tested on versions')
    versions = re.findall(r'\b\d+\.\d+\.\d+\b', lines[0].split('Tested on versions', 1)[1])
    if not versions:
        raise ValueError('Nelze určit podporovanou verzi Instagramu')
    return sorted(set(versions), key=lambda v: tuple(map(int, v.split('.'))), reverse=True)


def sha256(path):
    with open(path, 'rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def decrypted_macho(data):
    if len(data) < 32:
        raise ValueError('Missing Mach-O executable')
    magic = data[:4]
    if magic in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf'):
        n = struct.unpack_from('>I', data, 4)[0]
        stride = 32 if magic[-1] == 0xbf else 20
        if not 0 < n <= 32:
            raise ValueError('Invalid universal Mach-O')
        for i in range(n):
            pos = 8 + i * stride
            off, size = struct.unpack_from('>QQ' if stride == 32 else '>II', data, pos + 8)
            decrypted_macho(data[off:off + size])
        return
    formats = {b'\xcf\xfa\xed\xfe': ('<', 32), b'\xce\xfa\xed\xfe': ('<', 28),
               b'\xfe\xed\xfa\xcf': ('>', 32), b'\xfe\xed\xfa\xce': ('>', 28)}
    if magic not in formats:
        raise ValueError('Unsupported Mach-O format')
    endian, pos = formats[magic]
    n = struct.unpack_from(endian + 'I', data, 16)[0]
    for _ in range(n):
        cmd, size = struct.unpack_from(endian + 'II', data, pos)
        if size < 8 or pos + size > len(data):
            raise ValueError('Invalid Mach-O load command')
        if cmd in (0x21, 0x2c) and struct.unpack_from(endian + 'I', data, pos + 16)[0]:
            raise ValueError('IPA executable is still encrypted')
        pos += size


def extension_names(path):
    with zipfile.ZipFile(path) as z:
        return sorted({m.group(1) for n in z.namelist()
                       for m in [re.fullmatch(r'Payload/[^/]+\.app/(?:PlugIns|Extensions)/([^/]+\.appex)/Info\.plist', n)] if m})


def inspect(path, version=None, output=False, bundle_id='com.burbn.instagram', with_extensions=False):
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        plists = [n for n in names if re.fullmatch(r'Payload/[^/]+\.app/Info\.plist', n)]
        if len(plists) != 1:
            raise ValueError('Expected exactly one main app')
        p = plists[0]; root = p.rsplit('/', 1)[0] + '/'
        info = plistlib.loads(z.read(p))
        if info.get('CFBundleIdentifier') != bundle_id:
            raise ValueError('Expected ' + bundle_id)
        if version and info.get('CFBundleShortVersionString') != version:
            raise ValueError('Unsupported Instagram version: ' + str(info.get('CFBundleShortVersionString')))
        exe = info.get('CFBundleExecutable', '')
        if not exe or '/' in exe:
            raise ValueError('Invalid main executable')
        decrypted_macho(z.read(root + exe))
        if output:
            if not with_extensions and any('.appex/' in n for n in names):
                raise ValueError('App extensions remain in no-ext build')
            if with_extensions and not any('.appex/Info.plist' in n for n in names):
                raise ValueError('Expected extensions in standard release build')
            for suffix in ('Frameworks/Sparkle.dylib', 'Frameworks/SPKSideloadFix.dylib'):
                if root + suffix not in names:
                    raise ValueError('Missing ' + suffix)
            if not any('/Frameworks/spk.' in n and 'ffmpegkit' in n for n in names):
                raise ValueError('Missing Sparkle FFmpeg framework')
            if any('libFLEX' in n for n in names):
                raise ValueError('Unexpected FLEX debugger')
        elif any('Sparkle.dylib' in n or 'SCInsta.dylib' in n for n in names):
            raise ValueError('Input must be a clean IPA, not an injected build')
        return info
