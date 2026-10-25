"""Replay the supplied judge-2 suite once against frozen trees; never invoke authoring."""
import base64
from html.parser import HTMLParser
import tarfile
import urllib.request
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import zipfile

IMAGE = 'mcr.microsoft.com/playwright@sha256:ad57c625d284e8d287abcd40d18434582b2e354de71c8428cb080112b0c45960'
IMAGE_CONFIG = 'sha256:13de4df62c03eb78a52fb68400d08ce292fc9490fecf625ef8f5da6dc5b328b8'
REPOSITORY = 'pythonyx135793/bounty-arcade'
PROOF = Path(__file__).resolve().parent
MANIFEST = json.loads((PROOF / 'source-manifest.json').read_text())

def digest(data):
    return hashlib.sha256(data).hexdigest()

def write_json(file, value):
    file.write_text(json.dumps(value, indent=2) + '\n')

def run(args, log, *, timeout=180, cwd=None, check=True):
    started = time.time()
    with log.open('xb') as output:
        result = subprocess.run(args, cwd=cwd, stdin=subprocess.DEVNULL, stdout=output,
                                stderr=subprocess.STDOUT, timeout=timeout, check=False)
    receipt = {'args': args, 'exit_code': result.returncode, 'elapsed_seconds': time.time() - started}
    write_json(log.with_suffix('.receipt.json'), receipt)
    if check and result.returncode != 0:
        raise RuntimeError(f'Command failed: {args[0]}, {log.name}, exit {result.returncode}')
    return receipt

def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], timeout=90)

def verify_export(folder, files):
    for item in files:
        data = (folder / item['path']).read_bytes()
        if len(data) != item['bytes'] or digest(data) != item['sha256']:
            raise RuntimeError('Export mismatch: ' + item['path'])

def emit_observations(out):
    """Seal and emit lossless evidence in ordinary logs, without artifact/cache storage."""
    top_level = {
        'scope.json', 'source-identity.json', 'image-inspect.json', 'rebuilt-image-inspect.json', 'issuer-package-identity.json', 'matrix.json', 'host-error.json',
        'cleanup.json', 'ARCHIVE-AUDIT.json', 'ARTIFACTS.json',
        'base-container-inspect.json', 'candidate-container-inspect.json',
    }
    for stem in ['git-init', 'git-fetch', 'image-pull', 'image-build', 'base-container', 'candidate-container']:
        top_level.update([stem + '.log', stem + '.receipt.json'])
    side_names = {'runtime.json', 'resources.jsonl', 'logic.stdout.log', 'logic.stderr.log',
                  'browser.stdout.log', 'browser.stderr.log', 'report.json', 'steps.jsonl',
                  'receipt.json', 'harness-error.json'}
    proof_names = {'run-proof.py', 'run-side.cjs', 'step-reporter.cjs', 'source-manifest.json'}
    checker_names = {f['path'] for f in MANIFEST['checker_files']}
    patterns = [
        ('private-key', re.compile(rb'-----BEGIN (?:[A-Z0-9 ]+)?PRIVATE KEY-----')),
        ('key-like', re.compile(rb'\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{24,})\b')),
        ('authorization-header', re.compile(rb'(?i)\bauthorization["\\\s:]+(?:bearer|basic)\s+[A-Za-z0-9+/_.=-]{12,}')),
    ]
    scanned = []
    scan_limits = []

    def scan_bytes(name, data, nested=False):
        for kind, pattern in patterns:
            if pattern.search(data):
                # Never print the matched bytes. Withhold the archive for review.
                raise RuntimeError('Archive emission withheld: ' + kind + ' pattern in ' + name)
        scanned.append({'path': name, 'bytes': len(data), 'sha256': digest(data), 'nested': nested})
        if name.endswith('.zip'):
            if nested:
                raise RuntimeError('Unexpected archive nested inside a trace: ' + name)
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as trace:
                    for item in trace.infolist():
                        if item.is_dir():
                            continue
                        if item.file_size > 128 * 1024 * 1024 or Path(item.filename).is_absolute() or '..' in Path(item.filename).parts:
                            raise RuntimeError('Unexpected trace member: ' + name)
                        scan_bytes(name + '::' + item.filename, trace.read(item), nested=True)
            except zipfile.BadZipFile:
                # A killed browser can leave an incomplete trace; preserve those raw failure bytes.
                scan_limits.append({'path': name, 'limitation': 'Malformed trace ZIP retained byte-exact; nested content could not be fully inspected.'})

    for file in sorted(out.rglob('*')):
        if file.is_symlink():
            raise RuntimeError('Unexpected evidence symlink')
        if not file.is_file():
            continue
        rel = file.relative_to(out).as_posix()
        parts = rel.split('/')
        allowed = (rel in top_level
                   or (len(parts) == 2 and parts[0] == 'proof-scripts' and parts[1] in proof_names)
                   or (parts[0] == 'original-checker' and '/'.join(parts[1:]) in checker_names)
                   or (len(parts) == 2 and parts[0] in ['base', 'candidate'] and parts[1] in side_names)
                   or (len(parts) >= 3 and parts[0] in ['base', 'candidate'] and parts[1] == 'test-results'
                       and file.suffix in ['.zip', '.json', '.md', '.png', '.jpeg', '.webm', '.txt']))
        if not allowed:
            raise RuntimeError('Unexpected evidence path: ' + rel)
        scan_bytes(rel, file.read_bytes())
    write_json(out / 'ARCHIVE-AUDIT.json', {
        'status': 'ALLOWLIST_AND_SECRET_PATTERN_SCAN_PASS_WITH_LIMITS' if scan_limits else 'ALLOWLIST_AND_SECRET_PATTERN_SCAN_PASS',
        'scanned': scanned, 'scan_limits': scan_limits,
        'provenance': 'Public pinned sources and synthetic fresh browser contexts; no host home, credentials, Git config or provider environment mounted.',
        'limits': 'Pattern scan is an additional check, not proof against every possible secret format.'})
    artifacts = []
    for file in sorted(out.rglob('*')):
        if file.is_file() and file.name != 'ARTIFACTS.json':
            data = file.read_bytes()
            artifacts.append({'path': file.relative_to(out).as_posix(), 'bytes': len(data), 'sha256': digest(data)})
    write_json(out / 'ARTIFACTS.json', artifacts)
    archive_path = out.parent / 'observations.zip'
    with zipfile.ZipFile(archive_path, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for file in sorted(out.rglob('*')):
            if file.is_file():
                archive.write(file, file.relative_to(out).as_posix())
    with zipfile.ZipFile(archive_path) as archive:
        if archive.testzip() is not None:
            raise RuntimeError('Evidence ZIP CRC verification failed')
        for item in archive.infolist():
            if archive.read(item) != (out / item.filename).read_bytes():
                raise RuntimeError('Evidence ZIP readback differs')
    payload = archive_path.read_bytes()
    chunk_bytes = 12288
    total = (len(payload) + chunk_bytes - 1) // chunk_bytes
    metadata = {'format': 'zip+base64', 'archive': 'observations.zip', 'bytes': len(payload),
                'sha256': digest(payload), 'chunks': total, 'raw_bytes_per_chunk_max': chunk_bytes}
    print('ARCADE_R1599_ARCHIVE_BEGIN ' + json.dumps(metadata, separators=(',', ':')), flush=True)
    for index in range(total):
        chunk = payload[index * chunk_bytes:(index + 1) * chunk_bytes]
        encoded = base64.b64encode(chunk).decode('ascii')
        if base64.b64decode(encoded, validate=True) != chunk:
            raise RuntimeError('Base64 roundtrip differs')
        print(f'ARCADE_R1599_CHUNK {index + 1:06d}/{total:06d} {digest(chunk)} {encoded}', flush=True)
    print('ARCADE_R1599_ARCHIVE_END ' + json.dumps(metadata, separators=(',', ':')), flush=True)

def main():
    if (sys.platform != 'linux' or os.environ.get('GITHUB_ACTIONS') != 'true'
        or os.environ.get('GITHUB_REPOSITORY') != REPOSITORY
        or os.environ.get('GITHUB_EVENT_NAME') != 'push'
        or os.environ.get('GITHUB_REF') != 'refs/heads/codex/proof-arcade-r1599'
        or os.environ.get('GITHUB_RUN_ATTEMPT') != '1'):
        raise RuntimeError('Only the reviewed first-attempt exact-branch public-fork push may run this diagnostic')
    run_id = os.environ['GITHUB_RUN_ID']
    if not run_id.isdigit():
        raise RuntimeError('Invalid run ID')
    runner_temp = Path(os.environ['RUNNER_TEMP']).resolve()
    work = runner_temp / ('arcade-r1599-' + run_id)
    work.mkdir(exist_ok=False)
    out = work / 'out'
    out.mkdir()
    active_containers = []
    try:
        write_json(out / 'scope.json', {
            'classification': 'Independent replay of the supplied judge-2 suite; not a three-judge verdict or original image reproduction',
            'source_repository': REPOSITORY, 'workflow_commit': os.environ['GITHUB_SHA'],
            'run_id': run_id, 'attempt': 1, 'image': IMAGE, 'pins': {k: MANIFEST[k] for k in ['base', 'candidate', 'checker']},
            'limits': ['One execution per tree, sequential', '6 explicit workers, 30000ms timeout, 0 retries; 2 CPUs/4GiB/512PIDs/512MiB shm',
                       'Original npm script bodies; CLI adds worker count and observations',
                       'Supplied generated checks only; no authoring/provider/signing/payment/source edits or acceptance decision',
                       'Original public Dockerfile rebuilt on the pinned official base; local-only issuer binary image unavailable, new ID recorded']})
        shutil.copytree(PROOF, out / 'proof-scripts')
        repo = work / 'git'
        run(['git', 'init', str(repo)], out / 'git-init.log')
        run(['git', '-C', str(repo), 'fetch', '--no-tags', '--depth=1',
             'https://github.com/' + REPOSITORY + '.git', MANIFEST['base'], MANIFEST['candidate'], MANIFEST['checker']],
            out / 'git-fetch.log')
        class Downloads(HTMLParser):
            def __init__(self): super().__init__(); self.urls = []
            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == 'a' and attrs.get('href', '').startswith('data:application/zip;base64,'):
                    self.urls.append(attrs['href'])
        with urllib.request.urlopen(MANIFEST['issuer_report'], timeout=30) as response:
            html = response.read(3 * 1024 * 1024 + 1)
        if len(html) > 3 * 1024 * 1024: raise RuntimeError('Report exceeds reviewed bound')
        parser = Downloads(); parser.feed(html.decode('utf-8'))
        if len(parser.urls) != 1: raise RuntimeError('Expected one supplied ZIP link')
        package = base64.b64decode(parser.urls[0].split(',', 1)[1], validate=True)
        if len(package) != MANIFEST['issuer_archive_bytes'] or digest(package) != MANIFEST['issuer_archive_sha256']:
            raise RuntimeError('Supplied package changed; no execution')
        suite = {}
        with zipfile.ZipFile(io.BytesIO(package)) as supplied:
            if supplied.testzip() is not None or len(supplied.infolist()) != 22:
                raise RuntimeError('Supplied archive integrity differs')
            for entry in MANIFEST['issuer_suite_files']:
                data = supplied.read(entry['path'])
                if len(data) != entry['bytes'] or digest(data) != entry['sha256']:
                    raise RuntimeError('Supplied suite differs')
                suite[Path(entry['path']).name] = data
            dockerfile = supplied.read('Dockerfile.original')
        write_json(out / 'issuer-package-identity.json', {'bytes': len(package), 'sha256': digest(package),
            'suite': MANIFEST['issuer_suite_files'], 'executed_authoring': False})
        source_records = []
        for label in ['base', 'candidate']:
            commit = MANIFEST[label]
            tree = git(repo, 'rev-parse', commit + '^{tree}').decode().strip()
            listed = git(repo, 'ls-tree', '-r', '--name-only', commit).decode().splitlines()
            files = [f for f in MANIFEST['files'] if f['label'] == label]
            if sorted(listed) != sorted(f['path'] for f in files):
                raise RuntimeError('Full tree manifest differs: ' + label)
            folder = work / label
            folder.mkdir()
            for item in files:
                rel = Path(item['path'])
                if rel.is_absolute() or '..' in rel.parts:
                    raise RuntimeError('Unsafe source path')
                data = git(repo, 'show', commit + ':' + item['path'])
                blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
                if blob != item['git_blob'] or digest(data) != item['sha256']:
                    raise RuntimeError('Immutable Git bytes mismatch: ' + item['path'])
                target = folder / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            verify_export(folder, files)
            (folder / 'node_modules').symlink_to('/work/node_modules', target_is_directory=True)
            (folder / '_checks' / '2').mkdir(parents=True)
            for filename, data in suite.items(): (folder / '_checks' / '2' / filename).write_bytes(data)
            source_records.append({'label': label, 'commit': commit, 'tree': tree, 'files': len(files), 'all_git_bytes_and_sha256_match': True})
        checker_dir = out / 'original-checker'
        for item in MANIFEST['checker_files']:
            data = git(repo, 'show', MANIFEST['checker'] + ':' + item['path'])
            if digest(data) != item['sha256']:
                raise RuntimeError('Checker bytes mismatch')
            target = checker_dir / item['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        write_json(out / 'source-identity.json', source_records)
        for filename in ['package.json', 'package-lock.json']:
            if (work / 'base' / filename).read_bytes() != (work / 'candidate' / filename).read_bytes():
                raise RuntimeError('Dependencies differ')
        run(['docker', 'pull', '--platform=linux/amd64', IMAGE], out / 'image-pull.log', timeout=300)
        base_info = json.loads(subprocess.check_output(['docker', 'image', 'inspect', IMAGE], timeout=30))[0]
        if base_info['Id'] != IMAGE_CONFIG or base_info['Os'] != 'linux' or base_info['Architecture'] != 'amd64':
            raise RuntimeError('Pinned base image identity differs')
        write_json(out / 'image-inspect.json', base_info)
        context = work / 'image-context'; context.mkdir()
        with tarfile.open(fileobj=io.BytesIO(git(repo, 'archive', MANIFEST['checker']))) as archive:
            archive.extractall(context, filter='data')
        if (context / 'Dockerfile').read_bytes() != dockerfile:
            raise RuntimeError('Original public Dockerfile differs from supplied file')
        for filename in ['package.json', 'package-lock.json']:
            if (context / filename).read_bytes() != (work / 'base' / filename).read_bytes():
                raise RuntimeError('Image manifests differ from frozen application')
        subprocess.run(['docker', 'tag', IMAGE, 'mcr.microsoft.com/playwright:v1.49.1-noble'], check=True, timeout=30)
        rebuilt = 'arcade-r1599:' + run_id
        run(['docker', 'build', '--platform=linux/amd64', '--pull=false', '--progress=plain',
             '--tag', rebuilt, str(context)], out / 'image-build.log', timeout=600)
        info = json.loads(subprocess.check_output(['docker', 'image', 'inspect', rebuilt], timeout=30))[0]
        layers = base_info['RootFS']['Layers']
        if info['RootFS']['Layers'][:len(layers)] != layers:
            raise RuntimeError('Rebuilt image did not retain the pinned browser base')
        write_json(out / 'rebuilt-image-inspect.json', {'image': info, 'original_local_image': MANIFEST['original_local_image'],
            'same_image_id': info['Id'] == MANIFEST['original_local_image'], 'original_Dockerfile_unchanged': True,
            'unused_installed_CLI_not_invoked': True})
        bounties = work / 'checker-bounties'; bounties.mkdir()
        with tarfile.open(fileobj=io.BytesIO(git(repo, 'archive', MANIFEST['checker'], 'bounties'))) as archive:
            archive.extractall(bounties, filter='data')
        for label in ['base', 'candidate']:
            shutil.copytree(bounties / 'bounties', work / label / 'bounties')
        matrix = []
        for label in ['base', 'candidate']:
            name = 'arcade-r1599-' + run_id + '-' + label
            active_containers.append(name)
            command = ['docker', 'run', '--name', name, '--platform=linux/amd64', '--network', 'none',
                       '--mount', f'type=bind,src={work / label},dst=/evaluation',
                       '--mount', f'type=bind,src={PROOF},dst=/proof,readonly',
                       '--mount', f'type=bind,src={out},dst=/out', '--workdir', '/evaluation',
                       '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                       '--pids-limit', '512', '--memory', '4g', '--cpus', '2', '--shm-size', '512m',
                       '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m', '--user', f'{os.getuid()}:{os.getgid()}',
                       '--env', 'HOME=/tmp/arcade-home', rebuilt, 'node', '/proof/run-side.cjs', label]
            result = run(command, out / (label + '-container.log'), timeout=600, check=False)
            details = json.loads(subprocess.check_output(['docker', 'inspect', name], timeout=30))[0]
            config = details['HostConfig']
            observation = {'name': name, 'state': details['State'], 'image': details['Image'],
                           'network_mode': config['NetworkMode'], 'ipc_mode': config['IpcMode'],
                           'shm_bytes': config['ShmSize'], 'memory': config['Memory'],
                           'nano_cpus': config['NanoCpus'], 'cpu_quota': config['CpuQuota'],
                           'cpu_period': config['CpuPeriod'], 'cpuset_cpus': config['CpusetCpus'],
                           'mounts': details['Mounts']}
            if (config['NetworkMode'] != 'none' or config['Memory'] != 4 * 1024**3
                or config['NanoCpus'] != 2_000_000_000 or config['ShmSize'] != 512 * 1024**2
                or config['PidsLimit'] != 512 or not config['ReadonlyRootfs']
                or 'ALL' not in config['CapDrop'] or 'no-new-privileges' not in config['SecurityOpt']):
                raise RuntimeError('Test network isolation mismatch')
            write_json(out / (label + '-container-inspect.json'), observation)
            verify_export(work / label, [f for f in MANIFEST['files'] if f['label'] == label])
            matrix.append({'label': label, **result})
            # Any harness failure is evidence and stops the experiment; ordinary test failure still gets its paired control.
            if result['exit_code'] not in [0, 1]:
                raise RuntimeError('Container/harness failure, no automatic retry')
        write_json(out / 'matrix.json', {'matrix': matrix, 'original_acceptance': 'NOT PASS', 'no_retries': True})
        return 0 if matrix[0]['exit_code'] == 1 and matrix[1]['exit_code'] == 0 else 1
    except Exception as error:
        write_json(out / 'host-error.json', {'type': type(error).__name__, 'message': str(error)})
        raise
    finally:
        cleanup = []
        for name in reversed(active_containers):
            # Exact task-created containers only; collect logs before removing their ephemeral runtime.
            try:
                result = subprocess.run(['docker', 'rm', '--force', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
                cleanup.append({'name': name, 'exit_code': result.returncode})
            except Exception as error:
                cleanup.append({'name': name, 'error': type(error).__name__})
        write_json(out / 'cleanup.json', cleanup)
        emit_observations(out)

if __name__ == '__main__':
    sys.exit(main())
