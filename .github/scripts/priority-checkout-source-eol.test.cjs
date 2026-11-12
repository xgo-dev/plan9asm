'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const test = require('node:test');

const attributes = fs.readFileSync('.gitattributes', 'utf8');
const source = 'package fixture\n\nconst assembly = `TEXT original(SB),4,$0-0\nRET\n`\n' +
  'const oracle = `int main(void) { return 0; }\n`\nconst escaped = "\\r\\n"\n';
const fixtures = {
  'original.go': source,
  'nested/original_test.go': source,
  'original.s': 'TEXT original(SB),4,$0-0\nRET\n',
  'nested/conformance.s': fs.readFileSync('testdata/conformance/amd64/conformance_amd64.s', 'utf8'),
  'script.sh': '#!/bin/sh\nprintf "original\\n"\n',
  'ordinary.txt': 'ordinary text\nsecond line\n',
  'ordinary.asm': 'TEXT ordinary(SB),4,$0-0\nRET\n',
  'downloaded/original.s': 'TEXT downloaded(SB),4,$0-0\r\nRET\r\n',
};
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

function checkoutFixture(rules) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'plan9asm-checkout-eol-'));
  const environment = {...process.env};
  for (const key of Object.keys(environment)) {
    if (key.startsWith('GIT_')) delete environment[key];
  }
  Object.assign(environment, {
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: os.devNull, GIT_ATTR_NOSYSTEM: '1',
  });
  try {
    const git = args => {
      const result = spawnSync('git', ['-c', 'core.attributesFile=' + os.devNull,
        '-c', 'core.hooksPath=' + os.devNull, '-c', 'commit.gpgsign=false',
        '-c', 'user.name=Checkout fixture', '-c', 'user.email=fixture@example.invalid',
        '-C', directory, ...args], {
        env: environment, encoding: 'utf8', timeout: 5000,
      });
      assert.ifError(result.error);
      assert.equal(result.status, 0, result.stderr);
      return result.stdout;
    };
    git(['init', '--quiet']);
    git(['config', '--local', 'core.autocrlf', 'true']);
    git(['config', '--local', 'core.safecrlf', 'false']);
    fs.writeFileSync(path.join(directory, '.gitattributes'), rules);
    fs.writeFileSync(path.join(directory, '.gitignore'), 'downloaded/\n');
    for (const [name, text] of Object.entries(fixtures)) {
      const target = path.join(directory, name);
      fs.mkdirSync(path.dirname(target), {recursive: true});
      fs.writeFileSync(target, text);
    }
    git(['add', '.']);
    git(['commit', '--quiet', '-m', 'original fixture']);
    for (const name of Object.keys(fixtures)) {
      if (!name.startsWith('downloaded/')) fs.unlinkSync(path.join(directory, name));
    }
    // This actually restores bytes through Git's worktree conversion, not a
    // handcrafted CRLF replacement or a global user configuration change.
    git(['checkout-index', '--all', '--force']);
    return Object.fromEntries(Object.keys(fixtures).map(name =>
      [name, fs.readFileSync(path.join(directory, name))]));
  } finally {
    fs.rmSync(directory, {recursive: true, force: true});
  }
}

function requireOriginalSourceBytes(observed) {
  for (const name of ['original.go', 'nested/original_test.go', 'original.s', 'nested/conformance.s']) {
    assert.equal(digest(observed[name]), digest(Buffer.from(fixtures[name])),
      'checkout must preserve complete original repository Go/ASM/C bytes: ' + name);
    assert.equal(observed[name].includes(Buffer.from('\r\n')), false, name);
  }
  assert.equal(observed['script.sh'].toString(), fixtures['script.sh']);
  for (const name of ['ordinary.txt', 'ordinary.asm']) {
    assert.equal(observed[name].toString(), fixtures[name].replaceAll('\n', '\r\n'),
      'control must prove actual autocrlf conversion outside the source policy: ' + name);
  }
  assert.equal(digest(observed['downloaded/original.s']), digest(Buffer.from(fixtures['downloaded/original.s'])),
    'Git source policy must not normalize ignored external authority bytes');
}

test('actual autocrlf checkout preserves complete Go and ASM hashes without altering downloads', () => {
  requireOriginalSourceBytes(checkoutFixture(attributes));
});

test('checkout policy rejects missing substituted or CRLF Go and ASM rules using real Git controls', () => {
  const complete = '*.sh text eol=lf\n*.go text eol=lf\n*.s text eol=lf\n';
  requireOriginalSourceBytes(checkoutFixture(complete));
  for (const changed of [
    complete.replace('*.go text eol=lf\n', ''),
    complete.replace('*.go text', '*.notgo text'),
    complete.replace('*.go text eol=lf', '*.go text eol=crlf'),
    complete.replace('*.s text eol=lf\n', ''),
    complete.replace('*.s text', '*.notasm text'),
    complete.replace('*.s text eol=lf', '*.s text eol=crlf'),
  ]) {
    const observed = checkoutFixture(changed);
    assert.equal(observed['ordinary.txt'].toString(), fixtures['ordinary.txt'].replaceAll('\n', '\r\n'));
    assert.throws(() => requireOriginalSourceBytes(observed));
  }
});
