'use strict';
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');
const label = process.argv[2];
if (process.platform !== 'linux' || !['base', 'candidate'].includes(label) || process.cwd() !== '/evaluation') throw Error('Linux diagnostic container only');
const output = '/out/' + label;
fs.mkdirSync(output, { recursive: false });
const json = (name, data) => fs.writeFileSync(path.join(output, name), JSON.stringify(data, null, 2) + '\n');
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const manifest = JSON.parse(fs.readFileSync('/proof/source-manifest.json', 'utf8'));
const sourceFiles = manifest.files.filter(x => x.label === label);
fs.mkdirSync('/tmp/arcade-home', { recursive: true });
function verifySources() {
  for (const item of sourceFiles) {
    const bytes = fs.readFileSync(path.join('/evaluation', item.path));
    if (hash(bytes) !== item.sha256 || bytes.length !== item.bytes) throw Error('Source changed: ' + item.path);
  }
  for (const item of manifest.issuer_suite_files) {
    const bytes = fs.readFileSync('/evaluation/_checks/2/' + path.basename(item.path));
    if (bytes.length !== item.bytes || hash(bytes) !== item.sha256) throw Error('Supplied suite changed');
  }
  const pkg = JSON.parse(fs.readFileSync('/evaluation/package.json', 'utf8'));
  if (pkg.scripts.test !== 'npm run test:logic && npm run test:browser' || pkg.scripts['test:browser'] !== 'playwright test' || pkg.scripts['test:logic'] !== 'node --test apps/*/test/*.test.js ${CHECKS:+$CHECKS/*.test.js}') throw Error('Unexpected npm scripts');
}
function readOptional(file) { try { return fs.readFileSync(file, 'utf8'); } catch (e) { return { unavailable: e.code }; } }
function snapshot() {
  const files = ['/proc/loadavg', '/proc/meminfo', '/proc/self/status', '/proc/self/cgroup', '/proc/net/route', '/sys/fs/cgroup/cpu.max', '/sys/fs/cgroup/cpu.stat', '/sys/fs/cgroup/cpuset.cpus.effective', '/sys/fs/cgroup/memory.max', '/sys/fs/cgroup/memory.current', '/sys/fs/cgroup/memory.events', '/sys/fs/cgroup/pids.current'];
  return { at: new Date().toISOString(), logical_cpus: os.cpus().length, available_parallelism: os.availableParallelism(), free_memory: os.freemem(), files: Object.fromEntries(files.map(f => [f, readOptional(f)])) };
}
const samples = () => fs.appendFileSync(path.join(output, 'resources.jsonl'), JSON.stringify(snapshot()) + '\n');
function run(args, stage) {
  return new Promise(resolve => {
    const stdout = fs.openSync(path.join(output, stage + '.stdout.log'), 'wx');
    const stderr = fs.openSync(path.join(output, stage + '.stderr.log'), 'wx');
    const env = { PATH: process.env.PATH, HOME: '/tmp/arcade-home', TMPDIR: '/tmp', LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', PLAYWRIGHT_BROWSERS_PATH: '/ms-playwright',
      npm_config_cache: '/tmp/arcade-npm', npm_config_audit: 'false', npm_config_fund: 'false', npm_config_update_notifier: 'false', npm_config_fetch_retries: '0',
      CHECKS: '_checks/2', PLAYWRIGHT_JSON_OUTPUT_NAME: path.join(output, 'report.json'), ARCADE_OBSERVATION_DIR: output, DEBUG: 'pw:api,pw:browser' };
    const started_at = new Date().toISOString();
    const child = spawn('npm', args, { cwd: '/evaluation', env, detached: true, stdio: ['ignore', stdout, stderr] });
    fs.closeSync(stdout); fs.closeSync(stderr);
    let watchdog_fired = false, killTimer, error;
    const timer = setTimeout(() => { watchdog_fired = true; try { process.kill(-child.pid, 'SIGTERM'); } catch {} killTimer = setTimeout(() => { try { process.kill(-child.pid, 'SIGKILL'); } catch {} }, 5000); }, 600000);
    child.on('error', e => { error = String(e); });
    child.on('close', (exit_code, signal) => { clearTimeout(timer); clearTimeout(killTimer); resolve({ executable: 'npm', args, started_at, finished_at: new Date().toISOString(), exit_code, signal, error, watchdog_fired }); });
  });
}
(async () => {
  verifySources();
  if (process.version !== 'v22.12.0') throw Error('Issuer Node patch version differs');
  const versions = {};
  for (const name of ['@playwright/test', 'playwright', 'playwright-core', 'yaml']) {
    const file = '/work/node_modules/' + name + '/package.json';
    const bytes = fs.readFileSync(file);
    const pkg = JSON.parse(bytes);
    const expected = name === 'yaml' ? '2.6.1' : '1.49.1';
    if (pkg.version !== expected) throw Error('Dependency version mismatch: ' + name);
    versions[name] = { version: pkg.version, package_sha256: hash(bytes), scripts: pkg.scripts || {} };
  }
  const browserFiles = ['/ms-playwright/chromium-1148/chrome-linux/chrome', '/ms-playwright/chromium_headless_shell-1148/chrome-linux/headless_shell'];
  const browsers = browserFiles.map(file => ({ file, exists: fs.existsSync(file), sha256: fs.existsSync(file) ? hash(fs.readFileSync(file)) : null }));
  if (!browsers.every(b => b.exists)) throw Error('Pinned Chromium revision missing');
  json('runtime.json', { node: process.version, node_executable: process.execPath, node_sha256: hash(fs.readFileSync(process.execPath)), npm: spawnSync('npm', ['--version'], { encoding: 'utf8' }).stdout.trim(), platform: process.platform, arch: process.arch, release: os.release(), os_release: readOptional('/etc/os-release'), total_memory: os.totalmem(), snapshot: snapshot(), versions, browsers, browser_registry: JSON.parse(fs.readFileSync('/deps/node_modules/playwright-core/browsers.json', 'utf8')), command_limit: 'Original npm script bodies; explicit six workers and observation CLI options. Not literal npm test: same script bodies/order with the supplied suite, explicit six workers and observations; not a three-judge verdict.' });
  samples();
  const interval = setInterval(samples, 1000);
  let logic, browser, observation;
  try {
    logic = await run(['run', 'test:logic'], 'logic');
    if (logic.exit_code === 0) {
      browser = await run(['run', 'test:browser', '--', '--workers=6', '--trace=on', '--reporter=/proof/step-reporter.cjs,json', '--output=' + path.join(output, 'test-results')], 'browser');
      const events = fs.readFileSync(path.join(output, 'steps.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
      const begin = events.find(e => e.kind === 'begin');
      observation = { workers: begin?.workers, tests: begin?.tests.length, projects: begin?.projects, end: events.find(e => e.kind === 'end') };
      if (begin?.workers !== 6 || begin.tests.length !== (label === 'base' ? 10 : 13) || begin.projects.some(p => p.timeout !== 30000 || p.retries !== 0)) throw Error('Effective settings/test count mismatch');
    }
    const tap = fs.readFileSync(path.join(output, 'logic.stdout.log'), 'utf8');
    const logicTests = Number(tap.match(/^# tests (\d+)/m)?.[1]);
    const logicFailures = Number(tap.match(/^# fail (\d+)/m)?.[1]);
    if (label === 'candidate' && logic.exit_code === 0 && (logicTests !== 91 || logicFailures !== 0)) throw Error('Candidate logic coverage differs');
    if (label === 'base' && !(logic.exit_code === 1 && logicTests === 82 && logicFailures === 1 && tap.includes('ERR_ASSERTION') && tap.includes('the board app defines a [data-testid=search] control'))) throw Error('Baseline did not fail the expected missing-search assertion');
    verifySources();
    json('receipt.json', { label, commit: manifest[label], checker: manifest.checker, source_file_count: sourceFiles.length, source_verification: 'before and after match', logic, browser, observation, logicTests, logicFailures, classification: 'Supplied-suite six-worker replay only; original issuer acceptance remains NOT PASS', passed: logic.exit_code === 0 && browser?.exit_code === 0 });
    process.exitCode = logic.exit_code === 0 && browser?.exit_code === 0 ? 0 : 1;
  } finally { clearInterval(interval); samples(); }
})().catch(e => { json('harness-error.json', { at: new Date().toISOString(), error: e.stack }); process.exitCode = 2; });
