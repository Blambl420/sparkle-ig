import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

import ipa_checks


def request():
    for key, pattern in [('SOURCE_SHA', r'[0-9a-f]{40}'),
                         ('IG_VERSION', r'\d+\.\d+\.\d+'), ('SPARKLE_VERSION', r'\d+\.\d+\.\d+'),
                         ('TARGET_KEY', r'[0-9a-f]{24}'), ('REQUEST_ID', r'[0-9a-f]{24}')]:
        if not re.fullmatch(pattern, os.environ[key]):
            raise ValueError('Invalid ' + key)
    if os.environ.get('VERIFY_ONLY') == 'true':
        return
    if not re.fullmatch(r'[0-9a-f]{64}', os.environ['IPA_SHA256']):
        raise ValueError('Invalid IPA SHA256')
    if not re.fullmatch(r'https://altstore\.blambl\.cz/inbox/[0-9a-f]{32}/instagram\.ipa', os.environ['IPA_URL']):
        raise ValueError('Unexpected IPA source URL')
    print('::add-mask::' + os.environ['IPA_URL'])


def source_input():
    request()
    from ipa_checks import supported_versions
    version = os.environ['IG_VERSION']
    if version != supported_versions(Path('main/README.md').read_text())[0]:
        raise ValueError('Instagram version not the newest tested version of this release')
    if re.search(r'^Version:\s*(\S+)', Path('main/control').read_text(), re.M).group(1) != os.environ['SPARKLE_VERSION']:
        raise ValueError('Unexpected Sparkle version')
    if os.environ.get('VERIFY_ONLY') == 'true':
        return
    path = Path('main/packages/com.burbn.instagram.ipa'); path.parent.mkdir(exist_ok=True)
    with urllib.request.urlopen(os.environ['IPA_URL'], timeout=120) as r, path.open('wb') as f:
        shutil.copyfileobj(r, f)
    if ipa_checks.sha256(path) != os.environ['IPA_SHA256']:
        raise ValueError('Input SHA256 mismatch')
    info = ipa_checks.inspect(path, version)
    Path('input-info.json').write_text(json.dumps({'minimumOS': info.get('MinimumOSVersion', '15.0'),
                                                 'originalBuild': info['CFBundleVersion']}))


def output():
    version = os.environ['IG_VERSION']
    files = list(Path('main/packages').glob('Sparkle*no-ext*_IG_v*.ipa'))
    if len(files) != 1:
        raise ValueError('Expected one release IPA')
    original = files[0]
    info = ipa_checks.inspect(original, version, output=True)
    saved = json.loads(Path('input-info.json').read_text())
    build = os.environ['GITHUB_RUN_NUMBER'] + '.0.' + os.environ['GITHUB_RUN_ATTEMPT']
    minimum = max(saved['minimumOS'], info.get('MinimumOSVersion', '15.0'), key=lambda s: tuple(map(int, s.split('.'))))
    manifest = {'schema': 1, 'targetKey': os.environ['TARGET_KEY'], 'sourceSHA': os.environ['SOURCE_SHA'],
                'sparkleVersion': os.environ['SPARKLE_VERSION'], 'instagramVersion': version,
                'buildVersion': build, 'originalBuild': saved['originalBuild'], 'minimumOS': minimum,
                'inputSHA256': os.environ['IPA_SHA256'], 'profile': 'no-ext-no-flex-ffmpeg',
                'runId': os.environ['GITHUB_RUN_ID']}
    dist = Path('dist'); dist.mkdir(exist_ok=True)
    result = dist / f'Sparkle_no-flex_no-ext_v{manifest["sparkleVersion"]}_IG_v{version}_build{build}.ipa'
    with zipfile.ZipFile(original) as zin:
        plist_name = next(n for n in zin.namelist() if re.fullmatch(r'Payload/[^/]+\.app/Info\.plist', n))
        root = plist_name.rsplit('/', 1)[0]
        with tempfile.TemporaryDirectory() as temp:
            executable = Path(temp) / 'Instagram'
            executable.write_bytes(zin.read(root + '/' + info['CFBundleExecutable']))
            entitlements = subprocess.check_output(['ldid', '-e', str(executable)])
            plistlib.loads(entitlements)
        info['CFBundleVersion'] = build; info['MinimumOSVersion'] = minimum
        with zipfile.ZipFile(result, 'w', compression=zipfile.ZIP_DEFLATED) as zout:
            replace = {plist_name, root + '/archived-expanded-entitlements.xcent', root + '/BlamblBuild.json'}
            for entry in zin.infolist():
                if entry.filename not in replace:
                    with zin.open(entry) as src, zout.open(entry, 'w') as dst:
                        shutil.copyfileobj(src, dst)
            zout.writestr(plist_name, plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
            zout.writestr(root + '/archived-expanded-entitlements.xcent', entitlements)
            zout.writestr(root + '/BlamblBuild.json', json.dumps(manifest))
    checked = ipa_checks.inspect(result, version, output=True)
    if checked['CFBundleVersion'] != build:
        raise ValueError('Output build mismatch')
    manifest['sha256'] = ipa_checks.sha256(result)
    (dist / 'build.json').write_text(json.dumps(manifest, indent=2))
    (dist / 'notes.md').write_text(f'Sparkle {manifest["sparkleVersion"]} / Instagram {version} / build {build}.\n\n'
        f'No extensions, no FLEX; FFmpeg included. Minimum iOS {minimum}.\n\n'
        f'Sparkle by efibalogh, GPL-3.0. Complete tweak source: https://github.com/efibalogh/sparkle-ig/tree/{manifest["sourceSHA"]}\n'
        f'Build automation: https://github.com/{os.environ["GITHUB_REPOSITORY"]}/tree/{os.environ["GITHUB_SHA"]}/blambl\n\n'
        f'SHA256: {manifest["sha256"]}\n')


if __name__ == '__main__':
    {'request': request, 'input': source_input, 'output': output}[sys.argv[1]]()
