'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const {test} = require('node:test');

const action = fs.readFileSync('.github/actions/setup-go/action.yml', 'utf8');

test('Go setup keeps writable local caches without accessing the account cache quota', () => {
  assert.match(action, /^        cache: false$/m);
  assert.doesNotMatch(action, /^  cache:/m);
  for (const name of ['go-ci.yml', 'windows-module.yml', 'runtime-integration.yml', 'linux-cli-module.yml']) {
    const source = fs.readFileSync(path.join('.github/workflows', name), 'utf8');
    const steps = source.split(/(?=^      - )/m).filter(step =>
      /uses: \.\/\.github\/actions\/setup-go\n/.test(step));
    assert.ok(steps.length > 0, name);
    for (const step of steps) {
      assert.doesNotMatch(step, /^          cache:/m, name);
    }
  }
  for (const variable of ['GOPATH', 'GOBIN', 'GOMODCACHE', 'GOCACHE']) {
    assert.match(action, new RegExp('echo "' + variable + '=\\$\\{RUNNER_TEMP\\}/'));
  }
});

test('formal Go setup has its own bounded installation deadline', () => {
  for (const name of ['go-ci.yml', 'windows-module.yml', 'runtime-integration.yml', 'linux-cli-module.yml']) {
    const source = fs.readFileSync(path.join('.github/workflows', name), 'utf8');
    const steps = source.split(/(?=^      - )/m).filter(step =>
      /uses: \.\/\.github\/actions\/setup-go\n/.test(step));
    assert.ok(steps.length > 0, name);
    for (const step of steps) {
      assert.match(step, /^        timeout-minutes: 10$/m,
        name + ': downloads cannot consume the complete test job budget');
    }
  }
});

function verificationScript() {
  const step = action.split(/(?=^    - name:)/m).find(part =>
    part.startsWith('    - name: Verify Go installation\n'));
  assert.ok(step, 'setup must verify the actual Go command after the installer');
  assert.match(step, /REQUESTED_GO_VERSION: \$\{\{ inputs\.go-version \}\}/);
  assert.match(step, /INSTALLED_GO_VERSION: \$\{\{ steps\.install_go\.outputs\.go-version \}\}/);
  assert.doesNotMatch(step, /continue-on-error:|if:|\|\| true/);
  const start = step.indexOf('      run: |\n');
  assert.ok(start >= 0, 'the actual verification script is required');
  return step.slice(start + '      run: |\n'.length)
    .split('\n').map(line => line.startsWith('        ') ? line.slice(8) : line)
    .join('\n');
}

function verify(options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'plan9asm-go-install-'));
  try {
    if (!options.missingGo) {
      fs.writeFileSync(path.join(directory, 'go'), `#!/bin/sh
[ "$GOTOOLCHAIN" = local ] || exit 93
case "$*" in
  'env GOVERSION') printf 'go%s\\n' "$MOCK_GO_VERSION" ;;
  'version') printf 'go version go%s linux/amd64\\n' "$MOCK_GO_VERSION" ;;
  *) exit 92 ;;
esac
`, {mode: 0o755});
    }
    return spawnSync('/bin/bash', ['--noprofile', '--norc', '-c', verificationScript()], {
      encoding: 'utf8',
      timeout: 5000,
      env: {
        PATH: directory,
        REQUESTED_GO_VERSION: options.requested ?? '1.27.2',
        INSTALLED_GO_VERSION: options.installed ?? '1.27.2',
        MOCK_GO_VERSION: options.actual ?? '1.27.2',
        GOTOOLCHAIN: 'auto',
      },
    });
  } finally {
    fs.rmSync(directory, {recursive: true, force: true});
  }
}

test('setup verifies a real selected command without downloading another toolchain', () => {
  assert.match(action, /- name: Set up Go\n      id: install_go\n      uses: actions\/setup-go@v7/);
  assert.match(verificationScript(), /GOTOOLCHAIN=local go env GOVERSION/);
  const result = verify();
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Verified Go 1\.27\.2/);
});

test('historical minor selectors verify their own resolved stable patch', () => {
  for (const [requested, installed] of [['1.20.x', '1.20.14'], ['1.26.x', '1.26.8']]) {
    const result = verify({requested, installed, actual: installed});
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
  }
});

test('an interrupted installer cannot borrow a preinstalled Go or an empty output', () => {
  for (const options of [
    {missingGo: true},
    {installed: ''},
    {installed: '1.27.1'},
    {actual: '1.27.1'},
    {actual: '1.28.0'},
    {installed: '1.27.2rc1', actual: '1.27.2rc1'},
    {installed: '1.27.2\n1.27.2'},
    {actual: '1.27.2\n1.27.2'},
    {requested: '1.26.x'},
    {requested: ''},
    {requested: 'stable'},
  ]) {
    const result = verify(options);
    assert.ifError(result.error);
    assert.notEqual(result.status, 0, JSON.stringify(options));
    assert.doesNotMatch(result.stdout, /Verified Go/);
  }
});
