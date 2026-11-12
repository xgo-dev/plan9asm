'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {jobBody} = require('./workflow-needs.cjs');

const source = fs.readFileSync(path.join(__dirname, '../workflows/windows-module.yml'), 'utf8');
const jobs = ['root-parts', 'other-owners', 'complete'];
const exactSDK = '1.27.2';

// These independent jobs exchange one source/tool/environment-bound plan.
// A floating minor selector can resolve to a different SDK between execution
// and fresh completion. Pin the shared scope, never normalize its real hashes.
function requireExactSDK(workflow) {
  for (const name of jobs) {
    const body = jobBody(workflow, name);
    const steps = body.split(/(?=^      - )/m).slice(1);
    const setup = steps.filter(step =>
      /^      - uses: \.\/\.github\/actions\/setup-go$/m.test(step));
    assert.equal(setup.length, 1, name + ': one actual owned Go setup required');
    assert.doesNotMatch(body, /uses: actions\/setup-go@/,
      name + ': another Go installer cannot replace the owned setup');
    const versions = [...setup[0].matchAll(/^          go-version: (.+)$/gm)];
    assert.equal(versions.length, 1, name + ': one explicit Go pin required');
    assert.match(setup[0], /^        with:$/m, name + ': setup input scope missing');
    assert.ok(versions[0][1] === `'${exactSDK}'` || versions[0][1] === `"${exactSDK}"`,
      name + ': execution and completion require the same exact ' + exactSDK + ' SDK');
    assert.doesNotMatch(setup[0], /go-version-file:|check-latest:/,
      name + ': no alternative source may override the exact SDK');
  }
  assert.equal((workflow.match(/uses: \.\/\.github\/actions\/setup-go$/gm) || []).length, 3,
    'all shared Windows Go setup roles must be covered');
}

function replaceJob(workflow, name, change) {
  const before = jobBody(workflow, name);
  const after = change(before);
  assert.notEqual(after, before, 'negative control must mutate its actual job');
  return workflow.replace(before, after);
}

// Controls begin from a complete positive fixture even while the real source
// is RED. A matching pin in another job or run string is never a substitute.
const fixture = source.replace(/^          go-version: .+$/gm, `          go-version: '${exactSDK}'`);

test('shared Windows execution and fresh completion pin one exact SDK', () => {
  requireExactSDK(source);
});

test('main Windows caller retains the shared executor and aggregate scope', () => {
  for (const [file, name] of [
    ['go-ci.yml', 'windows-module'],
  ]) {
    const workflow = fs.readFileSync(path.join(__dirname, '../workflows', file), 'utf8');
    const body = jobBody(workflow, name);
    assert.match(body, /^    uses: \.\/\.github\/workflows\/windows-module\.yml$/m);
    assert.match(body, /^      module: \$\{\{ matrix\.module \}\}$/m);
    assert.doesNotMatch(body, /go-version:/,
      name + ': the shared scope must not inherit a floating caller selector');
  }
  requireExactSDK(fixture);
});

for (const name of jobs) {
  test(name + ' cannot use another patch, floating minor or dynamic SDK selector', () => {
    requireExactSDK(fixture);
    for (const version of ['1.27.3', '1.27.x', '1.27', 'stable', '${{ matrix.go }}']) {
      assert.throws(() => requireExactSDK(replaceJob(fixture, name, body =>
        body.replace(`go-version: '${exactSDK}'`, `go-version: '${version}'`))));
    }
  });

  test(name + ' cannot omit, duplicate or borrow its SDK pin', () => {
    const pin = `          go-version: '${exactSDK}'\n`;
    for (const replacement of ['', pin + pin, '          go-version-file: go.mod\n']) {
      assert.throws(() => requireExactSDK(replaceJob(fixture, name, body =>
        body.replace(pin, replacement))));
    }
    assert.throws(() => requireExactSDK(replaceJob(fixture, name, body =>
      body.replace(pin, '') + `      - run: echo "go-version: '${exactSDK}'"\n`)));
  });

  test(name + ' cannot lose or repeat the actual Go installer', () => {
    const setup = '      - uses: ./.github/actions/setup-go\n';
    assert.throws(() => requireExactSDK(replaceJob(fixture, name, body =>
      body.replace(setup, '      - uses: actions/setup-go@v7\n'))));
    assert.throws(() => requireExactSDK(replaceJob(fixture, name, body =>
      body.replace(setup, setup + `        with:\n          go-version: '${exactSDK}'\n` + setup))));
    assert.throws(() => requireExactSDK(replaceJob(fixture, name, body =>
      body.replace(`          go-version: '${exactSDK}'\n`,
        `          go-version: '${exactSDK}'\n          check-latest: true\n`))));
  });
}
