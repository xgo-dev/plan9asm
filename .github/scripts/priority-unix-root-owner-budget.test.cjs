'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {jobBody, requireJobNeeds} = require('./workflow-needs.cjs');

const workflow = fs.readFileSync(path.join(__dirname, '../workflows/go-ci.yml'), 'utf8');
const script = fs.readFileSync(path.join(__dirname, '../../scripts/test-module-ci.sh'), 'utf8');

function step(body, title) {
  const matches = body.split(/(?=^      - )/m).filter(value => value.startsWith(`      - name: ${title}\n`));
  assert.equal(matches.length, 1, 'one exact step required: ' + title);
  return matches[0];
}

function requireOwners(source, name) {
  const body = jobBody(source, name);
  const roles = Array.from({length: 16}, (_, index) => 'root-' + index).concat('profile', 'other');
  const axis = body.match(/^        module-role: \[([^\]]+)\]$/m);
  assert.ok(axis, name + ': explicit complete scheduling roles');
  assert.deepEqual(axis[1].split(',').map(value => value.trim()), roles);
  assert.deepEqual([...body.matchAll(
    /^          - \{module-role: (root-\d+|profile|other), module-owner: ([012]), root-partition: (-?\d+)\}$/gm,
  )].map(([, role, owner, part]) => [role, Number(owner), Number(part)]), [
    ...Array.from({length: 16}, (_, index) => ['root-' + index, 0, index]),
    ['profile', 1, -1], ['other', 2, -1],
  ]);
  assert.match(body, /^    needs: ci_policy$/m);
  assert.match(body, /^    timeout-minutes: 60$/m);
  assert.match(body, /^      fail-fast: false$/m);
  assert.doesNotMatch(body, /^    if:|max-parallel:|continue-on-error:|module-owner: \[/m);
  const title = name === 'test' ? 'Go test (Ubuntu)' : 'Go test with coverage';
  assert.ok(step(body, title).includes('run: bash scripts/test-module-ci.sh ' + name +
    ' execute ${{ matrix.module-owner }} ${{ matrix.root-partition }}\n'));
}

function requireDownloads(source) {
  const body = jobBody(source, 'module-completion');
  requireJobNeeds(source, 'module-completion', ['test', 'nested-cli', 'race', 'coverage', 'nested-cli-coverage']);
  assert.match(body, /^    if: \$\{\{ !cancelled\(\) \}\}$/m);
  for (let index = 0; index < 32; index++) {
    const download = step(body, 'Download root part ' + index);
    assert.ok(download.includes('name: module-${{ matrix.flavor }}-${{ matrix.go-version }}-root-' + index + '\n'));
    assert.ok(download.includes('path: _out/module-${{ matrix.flavor }}-owners/owner-0000/part-' +
      String(index).padStart(4, '0') + '\n'));
    if (index > 0 && index < 16) assert.match(download, /^        if: \$\{\{ !cancelled\(\) \}\}$/m);
    if (index < 16) assert.doesNotMatch(download, /^        if:.*matrix\.flavor/m);
    if (index >= 16) assert.match(download, /^        if: \$\{\{ !cancelled\(\) && matrix\.flavor == 'race' \}\}$/m);
  }
  assert.doesNotMatch(body, /merge-multiple:|pattern:/);
}

test('test and coverage retain all roots in sixteen independently budgeted owners', () => {
  requireOwners(workflow, 'test');
  requireOwners(workflow, 'coverage');
});

test('Unix root owners use one two-worker wave without raising any original budget', () => {
  assert.match(script, /^root_partitions=16$/m);
  assert.match(script, /^shards=32$/m);
  assert.match(script, /test\) timeout=45m ;;/);
  assert.match(script, /coverage\) timeout=45m; flags=\(-coverprofile=coverage-root\.out\) ;;/);
  assert.match(script, /race\) timeout=60m; flags=\(-race\); root_partitions=32; shards=64 ;;/);
  assert.equal([...script.matchAll(/-shards=\$shards -workers=2/g)].length, 2);
  assert.equal([...script.matchAll(/-module-root-partitions=\$root_partitions/g)].length, 2);
  assert.match(script, /GOMAXPROCS=2/);
  assert.match(jobBody(workflow, 'race'), /^    timeout-minutes: 75$/m);
  assert.match(jobBody(workflow, 'module-completion'), /^    timeout-minutes: 30$/m);
});

test('all flavors require exact root fragments zero through fifteen before complete readback', () => {
  requireDownloads(workflow);
});

test('lost or duplicated owners, stale eight-part readback and relaxed budgets are rejected', () => {
  for (const name of ['test', 'coverage']) {
    requireOwners(workflow, name);
    const body = jobBody(workflow, name);
    for (const [before, after] of [
      ['root-15,', ''],
      ['root-partition: 15', 'root-partition: 14'],
      ['timeout-minutes: 60', 'timeout-minutes: 75'],
      ['fail-fast: false', 'fail-fast: true'],
      ['timeout-minutes: 60', 'timeout-minutes: 60\n    continue-on-error: true'],
    ]) {
      const changed = body.replace(before, after);
      assert.notEqual(changed, body);
      assert.throws(() => requireOwners(workflow.replace(body, () => changed), name));
    }
  }
  requireDownloads(workflow);
  const complete = jobBody(workflow, 'module-completion');
  for (const index of [8, 15]) {
    const original = step(complete, 'Download root part ' + index);
    assert.throws(() => requireDownloads(workflow.replace(original, '')));
    const stale = original.replace('if: ${{ !cancelled() }}',
      "if: ${{ !cancelled() && matrix.flavor == 'race' }}");
    assert.notEqual(stale, original);
    assert.throws(() => requireDownloads(workflow.replace(original, () => stale)));
  }
});
