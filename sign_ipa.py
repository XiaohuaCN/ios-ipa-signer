#!/usr/bin/env python3
"""Fail-closed IPA resigning on disposable GitHub-hosted macOS runners."""
import base64
import datetime as dt
import hashlib
import html
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import secrets
import shutil
import stat
import subprocess
import sys
import urllib.parse
import urllib.request
import zipfile

MAX_SIZE = 4 * 1024**3


class ValidationError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise ValidationError(message)


def run(*args):
    result = subprocess.run(args, capture_output=True)
    if result.returncode != 0 and Path(args[0]).name == 'codesign':
        detail = result.stderr.decode('utf-8', errors='replace').strip()
        detail = re.sub(r'\b[A-Fa-f0-9]{40}\b', '<identity>', detail)
        runner_temp = os.environ.get('RUNNER_TEMP', '')
        if runner_temp:
            detail = detail.replace(runner_temp, '<runner-temp>')
        raise ValidationError(f"codesign failed: {detail[:500]}")
    require(result.returncode == 0, f"{Path(args[0]).name} failed; private tool output suppressed")
    return result.stdout


def run_with_secret_input(args, secret_input):
    """Run a command whose stdin contains sensitive data without exposing its output."""
    result = subprocess.run(args, input=secret_input, capture_output=True)
    require(result.returncode == 0, f"{Path(args[0]).name} failed; private tool output suppressed")


def decode(value):
    return base64.b64decode(''.join(value.split()), validate=True)


def allowed(actual, permitted):
    if isinstance(actual, str) and isinstance(permitted, str):
        return actual == permitted or (permitted.endswith('*') and actual.startswith(permitted[:-1]))
    if isinstance(actual, list) and isinstance(permitted, list):
        return all(any(allowed(x, p) for p in permitted) for x in actual)
    if isinstance(actual, dict) and isinstance(permitted, dict):
        return all(k in permitted and allowed(v, permitted[k]) for k, v in actual.items())
    return type(actual) is type(permitted) and actual == permitted


def make_entitlements(original, profile, bundle_id):
    grants = profile['Entitlements']
    prefix = profile['ApplicationIdentifierPrefix'][0]
    team = profile['TeamIdentifier'][0]
    app_id = prefix + '.' + bundle_id
    require(allowed(app_id, grants['application-identifier']), 'Profile does not allow Bundle ID')
    result = dict(original)
    old_prefix = original.get('application-identifier', '').split('.')[0]
    old_app_id = original.get('application-identifier', '')
    result['application-identifier'] = app_id
    result['com.apple.developer.team-identifier'] = team
    result['get-task-allow'] = grants.get('get-task-allow', False)
    if 'keychain-access-groups' in result and old_prefix:
        result['keychain-access-groups'] = [
            app_id if group == old_app_id else
            prefix + group[len(old_prefix):] if group.startswith(old_prefix + '.') else group
            for group in result['keychain-access-groups']]
    for key, value in result.items():
        require(key in grants and allowed(value, grants[key]),
                'An original entitlement is not permitted by the selected profile')
    return result


def inspect_zip(archive):
    total = 0
    seen = set()
    entries = archive.infolist()
    require(len(entries) <= 100000, 'Too many archive entries')
    for item in entries:
        path = PurePosixPath(item.filename)
        require(not path.is_absolute() and '..' not in path.parts and '\\' not in item.filename,
                'Unsafe archive path')
        require(path.parts, 'Empty archive path')
        require(not stat.S_ISLNK(item.external_attr >> 16), 'Symlink archives require a separately reviewed signing path')
        require(not item.flag_bits & 1, 'Password-encrypted ZIP is unsupported')
        key = str(path).casefold()
        require(key not in seen, 'Duplicate or case-colliding archive entry')
        seen.add(key)
        total += item.file_size
        require(total <= MAX_SIZE, 'Expanded IPA exceeds 4 GiB limit')


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        require(urllib.parse.urlsplit(newurl).scheme == 'https', 'HTTPS redirect required')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, destination, expected):
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password,
            'IPA source must be HTTPS without embedded user credentials')
    digest = hashlib.sha256()
    total = 0
    with urllib.request.build_opener(HTTPSRedirect()).open(url, timeout=60) as response, destination.open('wb') as out:
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            require(total <= MAX_SIZE, 'IPA exceeds 4 GiB limit')
            out.write(chunk)
            digest.update(chunk)
    require(digest.hexdigest() == expected.lower(), 'Source IPA SHA-256 mismatch')


def is_macho(path):
    with path.open('rb') as stream:
        return stream.read(4) in (bytes.fromhex(x) for x in (
            'feedface', 'cefaedfe', 'feedfacf', 'cffaedfe', 'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca'))


def main():
    require(sys.platform == 'darwin', 'Signing requires macOS')
    os.umask(0o077)
    for name in ('CERTIFICATE_ID', 'SOURCE_ID'):
        require(re.fullmatch(r'[A-Za-z0-9_]{1,40}', os.environ[name]), 'Invalid certificate/source ID')
    expected = os.environ['IPA_SHA256']
    require(re.fullmatch(r'[a-fA-F0-9]{64}', expected), 'A source SHA-256 is required')
    for name in ('P12_BASE64', 'PROFILE_BASE64'):
        require(os.environ.get(name), 'A required Actions Secret is missing')
    root = Path(os.environ['RUNNER_TEMP']) / 'ipa-signing'
    root.mkdir(mode=0o700)  # Refuse stale state.
    keychain = root / 'signing.keychain-db'
    installed = []
    try:
        ipa = root / 'source.ipa'
        if os.environ.get('IPA_SOURCE_URL'):
            download(os.environ['IPA_SOURCE_URL'], ipa, expected)
        else:
            local_source = Path(os.environ['RUNNER_TEMP']) / 'ipa-input/source.ipa'
            require(local_source.is_file() and local_source.stat().st_size <= MAX_SIZE, 'Private Release IPA is missing or too large')
            with local_source.open('rb') as stream:
                require(hashlib.file_digest(stream, 'sha256').hexdigest() == expected.lower(), 'Source IPA SHA-256 mismatch')
            shutil.copyfile(local_source, ipa)
        unpack = root / 'unpacked'
        with zipfile.ZipFile(ipa) as archive:
            inspect_zip(archive)
            archive.extractall(unpack, [x for x in archive.infolist() if PurePosixPath(x.filename).parts[0] == 'Payload'])
        payload = unpack / 'Payload'
        apps = list(payload.glob('*.app'))
        require(len(apps) == 1, 'Expected exactly one top-level app')
        app = apps[0]
        require(all(p == app for p in payload.iterdir()), 'Unexpected top-level Payload entry')
        original_bundle_id = plistlib.loads((app / 'Info.plist').read_bytes())['CFBundleIdentifier']
        profiles = []
        values = [os.environ['PROFILE_BASE64']]
        extra = json.loads(os.environ.get('EXTRA_PROFILES_JSON') or '[]')
        require(isinstance(extra, list) and all(isinstance(x, str) for x in extra), 'Extra profiles must be a JSON array of Base64 strings')
        values.extend(extra)
        for index, value in enumerate(values):
            path = root / f'profile-{index}.mobileprovision'
            path.write_bytes(decode(value))
            print(f'Stage: decode provisioning profile {index + 1}')
            profile = plistlib.loads(run('security', 'cms', '-D', '-i', str(path)))
            require(profile['ExpirationDate'] > dt.datetime.now(dt.timezone.utc).replace(tzinfo=None), 'Provisioning profile expired')
            require(profile.get('ProvisionsAllDevices') or profile.get('ProvisionedDevices'), 'Use an Ad Hoc, development or enterprise profile; App Store profiles do not support direct installation')
            profiles.append((path, profile))
        p12 = root / 'certificate.p12'
        pem = root / 'certificate-material.pem'
        compatible_p12 = root / 'certificate-compatible.p12'
        p12.write_bytes(decode(os.environ['P12_BASE64']))
        p12.chmod(0o600)
        password = secrets.token_urlsafe(32)
        print('Stage: create temporary keychain')
        run('security', 'create-keychain', '-p', password, str(keychain))
        run('security', 'set-keychain-settings', '-lut', '3600', str(keychain))
        run('security', 'unlock-keychain', '-p', password, str(keychain))
        run('security', 'list-keychains', '-d', 'user', '-s', str(keychain))
        print('Stage: import P12 certificate')
        # Re-export the same certificate and key with the runner's OpenSSL.
        # This lets macOS import valid P12 files produced by older tooling.
        p12_password = os.environ.get('P12_PASSWORD', '')
        password_input = (p12_password + '\n').encode()
        run_with_secret_input(
            ['openssl', 'pkcs12', '-in', str(p12), '-passin', 'stdin', '-nodes', '-out', str(pem)],
            password_input)
        run_with_secret_input(
            ['openssl', 'pkcs12', '-export', '-in', str(pem), '-out', str(compatible_p12),
             '-name', 'ios-signing', '-passout', 'stdin'],
            password_input)
        pem.chmod(0o600)
        compatible_p12.chmod(0o600)
        run('security', 'import', str(compatible_p12), '-P', p12_password, '-k', str(keychain), '-T', '/usr/bin/codesign')
        print('Stage: authorize codesign key access')
        run('security', 'set-key-partition-list', '-S', 'apple-tool:,apple:,codesign:', '-s', '-k', password, str(keychain))
        print('Stage: match signing identity to profiles')
        identities = set(re.findall(r'\b[A-Fa-f0-9]{40}\b', run('security', 'find-identity', '-v', '-p', 'codesigning', str(keychain)).decode()))
        compatible = set.intersection(*[
            {hashlib.sha1(cert).hexdigest().upper() for cert in profile['DeveloperCertificates']}
            for _, profile in profiles]) & {x.upper() for x in identities}
        require(len(compatible) == 1, 'Need exactly one valid P12 identity matching every profile')
        identity = compatible.pop()
        profile_dir = Path.home() / 'Library/MobileDevice/Provisioning Profiles'
        profile_dir.mkdir(parents=True, exist_ok=True)
        for index, (path, _) in enumerate(profiles):
            target = profile_dir / f'ipa-signer-{os.environ["GITHUB_RUN_ID"]}-{index}.mobileprovision'
            require(not target.exists(), 'Installed profile collision')
            installed.append(target)
            shutil.copyfile(path, target)
        bundles = [p for p in app.rglob('*') if p.is_dir() and p.suffix in ('.app', '.appex', '.framework', '.bundle')] + [app]
        signing = {}
        executables = set()
        for bundle in bundles:
            info_path = bundle / 'Info.plist'
            if not info_path.exists():
                require(bundle.suffix == '.bundle', 'Bundle missing Info.plist')
                continue
            info = plistlib.loads(info_path.read_bytes())
            executable_name = info.get('CFBundleExecutable')
            if not executable_name:
                require(bundle.suffix == '.bundle', 'Code bundle missing executable')
                continue
            require(Path(executable_name).name == executable_name, 'Unsafe executable name')
            executable = bundle / executable_name
            require(executable.is_file() and is_macho(executable), 'Bundle executable must be Mach-O')
            executables.add(executable)
            # Unsigned code has no original entitlements. Existing signed code must decode cleanly.
            original = {}
            check = subprocess.run(['codesign', '-d', '--entitlements', ':-', str(bundle)], capture_output=True)
            if check.returncode == 0 and check.stdout.strip():
                original = plistlib.loads(check.stdout)
            elif check.returncode != 0:
                require(b'code object is not signed at all' in check.stderr, 'Cannot read original signing entitlements')
            ent_path = None
            if bundle.suffix in ('.app', '.appex'):
                bundle_id = info['CFBundleIdentifier']
                matches = [(p, pr) for p, pr in profiles if allowed(
                    pr['ApplicationIdentifierPrefix'][0] + '.' + bundle_id,
                    pr['Entitlements']['application-identifier'])]
                require(len(matches) == 1, 'Each app/extension needs exactly one matching profile')
                source, profile = matches[0]
                ent = make_entitlements(original, profile, bundle_id)
                ent_path = root / f'entitlements-{len(signing)}.plist'
                ent_path.write_bytes(plistlib.dumps(ent))
                shutil.copyfile(source, bundle / 'embedded.mobileprovision')
            else:
                require(not original, 'Framework/bundle entitlements require manual review')
            signing[bundle] = ent_path
        for path in app.rglob('*'):
            if path.is_file() and is_macho(path):
                load_commands = run('otool', '-l', str(path))
                require(not re.search(rb'\bcryptid\s+[1-9][0-9]*', load_commands), 'Encrypted App Store executable cannot be re-signed')
                path.chmod(path.stat().st_mode | 0o111)
                if path not in executables:
                    signing[path] = None
        for target in sorted(signing, key=lambda p: len(p.parts), reverse=True):
            print(f'Stage: sign {target.relative_to(unpack)}')
            args = ['codesign', '--force', '--sign', identity, '--timestamp=none', '--generate-entitlement-der']
            if signing[target]:
                args.extend(['--entitlements', str(signing[target])])
            run(*args, str(target))
            print(f'Stage: verify {target.relative_to(unpack)}')
            run('codesign', '--verify', '--strict', str(target))
        print('Stage: verify final app bundle')
        run('codesign', '--verify', '--deep', '--strict', str(app))
        output = Path('dist')
        output.mkdir(exist_ok=True)
        signed = output / 'signed.ipa'
        with zipfile.ZipFile(signed, 'w', zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(payload.rglob('*')):
                archive.write(path, path.relative_to(unpack))
        with zipfile.ZipFile(signed) as archive:
            final_info = plistlib.loads(archive.read(str(app.relative_to(unpack) / 'Info.plist')))
        with signed.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        metadata = dict(schema_version=1, status='signed', artifact='signed.ipa', sha256=digest,
                        bundle_id=final_info['CFBundleIdentifier'], version=final_info['CFBundleShortVersionString'],
                        build=final_info['CFBundleVersion'], certificate_id=os.environ['CERTIFICATE_ID'],
                        source_id=os.environ['SOURCE_ID'], job_id=os.environ.get('JOB_ID', ''),
                        app_id=os.environ.get('APP_ID', ''), run_id=os.environ['GITHUB_RUN_ID'],
                        original_bundle_id=original_bundle_id, storage_url=None, publication_status='not_configured')
        (output / 'metadata.json').write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + '\n')
        (output / 'signed.ipa.sha256').write_text(digest + '  signed.ipa\n')
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
                summary.write('### Signed IPA verified\n\n<table>')
                for key in ('bundle_id', 'version', 'build', 'certificate_id', 'sha256'):
                    summary.write('<tr><th>' + key + '</th><td>' + html.escape(str(metadata[key])) + '</td></tr>')
                summary.write('</table>\n\nOSS / Cloudflare publication: not configured.\n')
        print('Signed IPA verified and packaged. OSS/D1 publication is not configured.')
    finally:
        if keychain.exists():
            subprocess.run(['security', 'delete-keychain', str(keychain)], capture_output=True)
        for path in installed:
            path.unlink(missing_ok=True)
        shutil.rmtree(root, ignore_errors=True)


if __name__ == '__main__':
    try:
        main()
    except ValidationError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('Signing failed; sensitive exception details suppressed.', file=sys.stderr)
        sys.exit(1)
