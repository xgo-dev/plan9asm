'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const {test} = require('node:test');

const action = fs.readFileSync('.github/actions/setup-node22/action.yml', 'utf8');

function verificationScript() {
  const step = action.split(/(?=^    - name:)/m).find(part =>
    part.startsWith('    - name: Verify Node.js installation\n'));
  if (!step) return '';
  const marker = '      run: |\n';
  assert.ok(step.includes(marker), 'verification requires the actual script');
  return step.slice(step.indexOf(marker) + marker.length)
    .split('\n').map(line => line.startsWith('        ') ? line.slice(8) : line).join('\n');
}

function verify(options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'plan9asm-node22-install-'));
  try {
    if (!options.missingNode) {
      fs.writeFileSync(path.join(directory, 'node'), `#!/bin/sh
[ "$*" = '--version' ] || exit 92
printf '%s\\n' "$MOCK_NODE_VERSION"
exit "$MOCK_NODE_EXIT"
`, {mode: 0o755});
    }
    return spawnSync('/bin/bash', ['--noprofile', '--norc', '-c', verificationScript()], {
      encoding: 'utf8', timeout: 5000,
      env: {
        PATH: directory,
        EXPECTED_NODE_VERSION: 'v22.23.4',
        INSTALLED_NODE_VERSION: options.installed ?? 'v22.23.4',
        MOCK_NODE_VERSION: options.actual ?? 'v22.23.4',
        MOCK_NODE_EXIT: String(options.exit ?? 0),
      },
    });
  } finally {
    fs.rmSync(directory, {recursive: true, force: true});
  }
}

test('Node setup pins one exact runtime and verifies its official installer output', () => {
  assert.match(action, /id: install_node22\n      uses: actions\/setup-node@v6\n      with:\n        node-version: '22\.23\.4'/);
  assert.match(action, /INSTALLED_NODE_VERSION: \$\{\{ steps\.install_node22\.outputs\.node-version \}\}/);
  assert.match(action, /EXPECTED_NODE_VERSION: 'v22\.23\.4'/);
  assert.doesNotMatch(action, /continue-on-error:|\n      if:|\|\|\s*true|node-version-file:|mirror:/);
  assert.ok(verificationScript().includes('set -euo pipefail'));
});

test('a complete exact Node installation selects its actual PATH runtime', () => {
  for (const actual of ['v22.23.4', 'v22.23.4\r']) {
    const result = verify({actual});
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Verified Node v22\.23\.4: .*\/node/);
  }
});

test('an interrupted Node download cannot borrow an ambient runtime or empty output', () => {
  for (const options of [
    {installed: ''},
    {installed: '', actual: 'v22.23.3'},
    {installed: '', actual: 'v22.23.4'},
    {missingNode: true},
    {actual: 'v22.23.3'},
    {actual: 'v24.0.0'},
    {actual: '', exit: 1},
    {actual: 'v22.23.4', exit: 1},
  ]) {
    const result = verify(options);
    assert.ifError(result.error);
    assert.notEqual(result.status, 0, JSON.stringify(options));
    assert.doesNotMatch(result.stdout, /Verified Node/);
  }
});

test('Node verification rejects wrong patches, nonstable versions and malformed output', () => {
  for (const value of ['v22.23.3', '22.23.4', 'v22.23.4-rc.1', 'v24.0.0',
    'v22.23.4\nv22.23.4', ' v22.23.4', 'v22.23.4 ']) {
    for (const options of [{installed: value}, {actual: value}]) {
      const result = verify(options);
      assert.ifError(result.error);
      assert.notEqual(result.status, 0, JSON.stringify(options));
      assert.doesNotMatch(result.stdout, /Verified Node/);
    }
  }
});
