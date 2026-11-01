const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const {test} = require('node:test');

const root = path.join(__dirname, '../..');
const installer = path.join(root, 'scripts/install-ci-llvm22-ubuntu.sh');
const configure = path.join(root, 'scripts/configure-ci-ubuntu-mirrors.py');
const badMirrors = 'https:/us.archive.ubuntu.com/ubuntu\n' +
  'https://mirrors.edge.kernel.org/ubuntu\n';
const sources = 'Types: deb\nURIs: mirror+file:/etc/apt/apt-mirrors.txt\n' +
  'Suites: noble noble-updates noble-backports\n' +
  'Components: main universe restricted multiverse\n' +
  'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n';

function fixture(t, mirrors = true) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'plan9asm-ubuntu-apt-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  if (mirrors) {
    for (const file of ['apt-mirrors.txt', 'apt-mirrors-security.txt']) {
      fs.writeFileSync(path.join(directory, file), badMirrors);
    }
  }
  fs.writeFileSync(path.join(directory, 'ubuntu.sources'), sources);
  fs.writeFileSync(path.join(directory, 'custom-mirrors.txt'), 'https://apt.llvm.org/noble/\n');
  return directory;
}

function runConfigure(directory, architecture) {
  const result = spawnSync('python3', [configure, directory, architecture], {
    encoding: 'utf8', timeout: 5000,
    env: {...process.env, PYTHONDONTWRITEBYTECODE: '1'},
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  return result.stdout;
}

function assertUnchangedSources(directory) {
  assert.equal(fs.readFileSync(path.join(directory, 'ubuntu.sources'), 'utf8'), sources);
  assert.equal(fs.readFileSync(path.join(directory, 'custom-mirrors.txt'), 'utf8'),
    'https://apt.llvm.org/noble/\n');
}

test('Ubuntu mirror configuration repairs the actual malformed runner lists only', t => {
  for (const [architecture, archive, security] of [
    ['amd64', 'https://archive.ubuntu.com/ubuntu/', 'https://security.ubuntu.com/ubuntu/'],
    ['i386', 'https://archive.ubuntu.com/ubuntu/', 'https://security.ubuntu.com/ubuntu/'],
    ['arm64', 'https://ports.ubuntu.com/ubuntu-ports/', 'https://ports.ubuntu.com/ubuntu-ports/'],
    ['armhf', 'https://ports.ubuntu.com/ubuntu-ports/', 'https://ports.ubuntu.com/ubuntu-ports/'],
  ]) {
    const directory = fixture(t);
    assert.equal(runConfigure(directory, architecture), archive + '\n');
    assert.equal(runConfigure(directory, architecture), archive + '\n');
    assert.equal(fs.readFileSync(path.join(directory, 'apt-mirrors.txt'), 'utf8'), archive + '\n');
    assert.equal(fs.readFileSync(path.join(directory, 'apt-mirrors-security.txt'), 'utf8'), security + '\n');
    assertUnchangedSources(directory);
  }
});

test('Ubuntu direct sources do not acquire new mirror lists or unrelated configuration', t => {
  const directory = fixture(t, false);
  runConfigure(directory, 'amd64');
  assert.deepEqual(fs.readdirSync(directory).sort(), ['custom-mirrors.txt', 'ubuntu.sources']);
  assertUnchangedSources(directory);
});

// Execute the actual Bash installer. Every privileged/network/package command
// is intercepted; only the real narrow helper runs against this test's directory.
function runInstaller(t, options = {}) {
  const directory = fixture(t);
  const environment = path.join(directory, 'environment');
  const script = `
updates=0
installs=0
IFS=, read -r -a update_statuses <<< "$MOCK_UPDATES"
IFS=, read -r -a install_statuses <<< "$MOCK_INSTALLS"
dpkg() {
  case "$1" in
    -s) return "$MOCK_INSTALLED" ;;
    --print-architecture)
      printf 'DPKG_ARCH\\n' >&2
      if [[ "$MOCK_ARCH_EXIT" != 0 ]]; then return "$MOCK_ARCH_EXIT"; fi
      printf '%s\\n' "$MOCK_ARCH" ;;
    *) return 99 ;;
  esac
}
lsb_release() { test "$1" = -cs && printf 'noble\\n'; }
curl() {
  printf 'CURL'; printf ' <%s>' "$@"; printf '\\n' >&2
  printf 'test signing key\\n'
}
tee() {
  case "$1" in
    /etc/apt/trusted.gpg.d/llvm-snapshot.asc|/etc/apt/sources.list.d/llvm.list|/etc/apt/sources.list.d/plan9asm-ci-fallback.list)
      command tee "$MOCK_APT/$(basename "$1")" ;;
    *) return 99 ;;
  esac
}
env() {
  test "$1" = DEBIAN_FRONTEND=noninteractive || return 99
  shift
  "$@"
}
timeout() {
  test "$1" = -k && test "$2" = 10s || return 99
  case "$3" in 2m|4m) ;; *) return 99 ;; esac
  printf 'TIMEOUT %s\\n' "$3"
  shift 3
  "$@"
}
apt-get() {
  printf 'APT_BEGIN\\n' >&2
  printf 'APT'; printf ' <%s>' "$@"; printf '\\n'
  for arg in "$@"; do
    case "$arg" in
      update)
        updates=$((updates + 1))
        return "\${update_statuses[updates - 1]:-99}" ;;
      install)
        installs=$((installs + 1))
        return "\${install_statuses[installs - 1]:-99}" ;;
    esac
  done
  return 99
}
sudo() {
  case "$1" in
    tee|timeout) "$@" ;;
    python3)
      test "$#" = 4 && test "$3" = /etc/apt || return 99
      printf 'CONFIGURE %s\\n' "$4" >&2
      if [[ "$MOCK_CONFIG_EXIT" != 0 ]]; then return "$MOCK_CONFIG_EXIT"; fi
      if [[ "$MOCK_CONFIG_OUTPUT" != __actual_helper__ ]]; then
        printf '%s' "$MOCK_CONFIG_OUTPUT"
      else
        command python3 "$2" "$MOCK_APT" "$4"
      fi ;;
    *) return 99 ;;
  esac
}
llvm-config-22() { printf '%s\\n' "$MOCK_LLVM_VERSION"; }
clang-22() { return 0; }
llc-22() { return 0; }
source "$1" gcc-i686-linux-gnu libc6-dev-i386-cross
`;
  const result = spawnSync('bash', ['--noprofile', '--norc', '-c', script, 'installer-test', installer], {
    encoding: 'utf8', timeout: 5000,
    env: {
      ...process.env, PYTHONDONTWRITEBYTECODE: '1',
      MOCK_APT: directory, MOCK_ARCH: options.architecture || 'amd64',
      MOCK_ARCH_EXIT: String(options.architectureExit || 0),
      MOCK_INSTALLED: options.installed ? '0' : '1',
      MOCK_UPDATES: (options.updates || [0]).join(','),
      MOCK_INSTALLS: (options.installs || [0]).join(','),
      MOCK_CONFIG_EXIT: String(options.configurationExit || 0),
      MOCK_CONFIG_OUTPUT: options.configurationOutput === undefined
        ? '__actual_helper__' : options.configurationOutput,
      MOCK_LLVM_VERSION: options.version || '22.1.8', GITHUB_ENV: environment,
    },
  });
  assert.ifError(result.error);
  return {...result, directory, environment: fs.existsSync(environment)
    ? fs.readFileSync(environment, 'utf8') : ''};
}

test('actual Ubuntu installer configures mirrors before strict IPv4 update and install', t => {
  const result = runInstaller(t);
  assert.equal(result.status, 0, result.stderr);
  assert.ok(result.stderr.indexOf('CONFIGURE amd64\n') >= 0, result.stderr);
  assert.ok(result.stderr.indexOf('CONFIGURE amd64\n') < result.stderr.indexOf('APT_BEGIN\n'), result.stderr);
  for (const command of result.stdout.split('\n').filter(line => line.startsWith('APT '))) {
    for (const option of ['Acquire::ForceIPv4=true', 'APT::Update::Error-Mode=any',
      'Acquire::Retries=2', 'Acquire::http::Timeout=30', 'Acquire::https::Timeout=30']) {
      assert.ok(command.includes('<' + option + '>'), command);
    }
  }
  assert.match(result.stdout, /TIMEOUT 2m\n/);
  assert.match(result.stdout, /TIMEOUT 4m\n/);
  assert.match(result.stdout, /<install> <-y> <llvm-22-dev> <clang-22> <libclang-22-dev> <lld-22> <libunwind-22-dev> <libc\+\+-22-dev> <gcc-i686-linux-gnu> <libc6-dev-i386-cross>/);
  assert.equal(fs.readFileSync(path.join(result.directory, 'apt-mirrors.txt'), 'utf8'),
    'https://archive.ubuntu.com/ubuntu/\n');
  assertUnchangedSources(result.directory);
  assert.match(result.environment, /^PATH=\/usr\/lib\/llvm-22\/bin:/);
});

test('already installed LLVM packages need no mirror change, update or download', t => {
  const result = runInstaller(t, {installed: true});
  assert.equal(result.status, 0, result.stderr);
  assert.doesNotMatch(result.stdout + result.stderr, /DPKG_ARCH|CONFIGURE|APT |CURL|TIMEOUT/);
  assert.equal(fs.readFileSync(path.join(result.directory, 'apt-mirrors.txt'), 'utf8'), badMirrors);
  assertUnchangedSources(result.directory);
  assert.match(result.environment, /^PATH=\/usr\/lib\/llvm-22\/bin:/);
});

test('two exhausted updates retain exit 124 without installation or PATH publication', t => {
  const result = runInstaller(t, {updates: [124, 124]});
  assert.equal(result.status, 124, result.stderr);
  const commands = result.stdout.split('\n').filter(line => line.startsWith('APT '));
  assert.equal(commands.length, 2);
  assert.ok(commands.every(line => line.endsWith('<update>')));
  assert.match(commands[1], /<Dir::Etc::sourcelist=\/etc\/apt\/sources.list.d\/plan9asm-ci-fallback.list>/);
  assert.match(commands[1], /<Dir::Etc::sourceparts=->/);
  assert.equal(result.environment, '');
});

test('fallback keeps strict network options, the identical package transaction and original budgets', t => {
  const result = runInstaller(t, {updates: [0, 0], installs: [100, 0]});
  assert.equal(result.status, 0, result.stderr);
  const commands = result.stdout.split('\n').filter(line => line.startsWith('APT '));
  assert.equal(commands.length, 4);
  for (const command of commands) {
    assert.match(command, /<Acquire::ForceIPv4=true>/);
    assert.match(command, /<APT::Update::Error-Mode=any>/);
  }
  assert.equal(commands[1].slice(commands[1].indexOf('<install>')),
    commands[3].slice(commands[3].indexOf('<install>')));
  assert.equal((result.stdout.match(/^TIMEOUT 2m$/gm) || []).length, 2);
  assert.equal((result.stdout.match(/^TIMEOUT 4m$/gm) || []).length, 2);
});

test('isolated fallback uses the same official Ubuntu architecture route as the repaired mirror lists', async t => {
  for (const [architecture, archive] of [
    ['amd64', 'https://archive.ubuntu.com/ubuntu/'],
    ['i386', 'https://archive.ubuntu.com/ubuntu/'],
    ['arm64', 'https://ports.ubuntu.com/ubuntu-ports/'],
    ['armhf', 'https://ports.ubuntu.com/ubuntu-ports/'],
  ]) {
    await t.test(architecture, child => {
      const result = runInstaller(child, {architecture, updates: [124, 0]});
      assert.equal(result.status, 0, result.stderr);
      const key = '[signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg]';
      const components = 'main universe restricted multiverse';
      assert.equal(fs.readFileSync(path.join(result.directory, 'plan9asm-ci-fallback.list'), 'utf8'),
        `deb ${key} ${archive} noble ${components}\n` +
        `deb ${key} ${archive} noble-updates ${components}\n` +
        'deb https://apt.llvm.org/noble/ llvm-toolchain-noble-22 main\n');
      assert.equal(fs.readFileSync(path.join(result.directory, 'apt-mirrors.txt'), 'utf8'), archive + '\n');
      const commands = result.stdout.split('\n').filter(line => line.startsWith('APT '));
      assert.equal(commands.length, 3);
      assert.equal((result.stderr.match(/^DPKG_ARCH$/gm) || []).length, 1);
      assert.ok(commands[0].endsWith('<update>'));
      assert.ok(commands[1].endsWith('<update>'));
      assert.ok(commands[2].includes('<install>'));
      assertUnchangedSources(result.directory);
    });
  }
});

test('failed fallback update cannot fall through to missing-package installation or publish PATH', t => {
  const result = runInstaller(t, {updates: [124, 100]});
  assert.equal(result.status, 100, result.stderr);
  const commands = result.stdout.split('\n').filter(line => line.startsWith('APT '));
  assert.equal(commands.length, 2);
  for (const command of commands) {
    assert.ok(command.endsWith('<update>'));
    assert.match(command, /<APT::Update::Error-Mode=any>/);
  }
  assert.equal(result.environment, '');
});

test('invalid mirror helper output or helper failure cannot reach APT or publish PATH', async t => {
  for (const [name, configurationOutput] of [
    ['empty', ''],
    ['foreign URL', 'https://example.invalid/ubuntu/\n'],
    ['diagnostic prefix', 'CONFIGURE amd64\nhttps://archive.ubuntu.com/ubuntu/\n'],
    ['extra source', 'https://archive.ubuntu.com/ubuntu/\nextra-source\n'],
  ]) {
    await t.test(name, child => {
      const result = runInstaller(child, {configurationOutput});
      assert.equal(result.status, 1, result.stderr);
      assert.match(result.stderr, /invalid Ubuntu archive mirror/);
      assert.doesNotMatch(result.stdout, /APT |TIMEOUT/);
      assert.equal(result.environment, '');
    });
  }
  await t.test('failure exit', child => {
    const result = runInstaller(child, {configurationExit: 68});
    assert.equal(result.status, 68, result.stderr);
    assert.doesNotMatch(result.stdout, /APT |TIMEOUT/);
    assert.equal(result.environment, '');
  });
});

test('failed architecture query cannot silently select the ports route', t => {
  const result = runInstaller(t, {architectureExit: 67});
  assert.equal(result.status, 67, result.stderr);
  assert.doesNotMatch(result.stdout + result.stderr, /CONFIGURE|APT |TIMEOUT/);
  assert.equal(result.environment, '');
});

test('failed package installation and wrong LLVM version cannot publish success', t => {
  const failed = runInstaller(t, {updates: [0, 0], installs: [100, 101]});
  assert.equal(failed.status, 101, failed.stderr);
  assert.equal(failed.environment, '');
  for (const installed of [false, true]) {
    const wrong = runInstaller(t, {installed, version: '23.0.0'});
    assert.equal(wrong.status, 1, wrong.stderr);
    assert.match(wrong.stderr, /does not select LLVM 22/);
    assert.equal(wrong.environment, '');
  }
});
