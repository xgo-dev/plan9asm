'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {jobBody, requireJobNeeds} = require('./workflow-needs.cjs');

const workflow = fs.readFileSync(path.join(__dirname, '../workflows/go-ci.yml'), 'utf8');
const script = fs.readFileSync(path.join(__dirname, '../../scripts/test-module-ci.sh'), 'utf8');

function step(body, title) {
  const selected = body.split(/(?=^      - )/m).filter(item => item.startsWith(`      - name: ${title}\n`));
  assert.equal(selected.length, 1, 'one exact complete-owner step required: ' + title);
  return selected[0];
}

function requireRaceOwners(source) {
  const body = jobBody(source, 'race');
  const roles = Array.from({length: 32}, (_, index) => 'root-' + index).concat('profile', 'other');
  const axis = body.match(/^        module-role: \[([^\]]+)\]$/m);
  assert.ok(axis, 'explicit complete race scheduling owners');
  assert.deepEqual(axis[1].split(',').map(value => value.trim()), roles);
  const mappings = [...body.matchAll(
    /^          - \{module-role: (root-\d+|profile|other), module-owner: ([012]), root-partition: (-?\d+)\}$/gm,
  )].map(([, role, owner, part]) => [role, Number(owner), Number(part)]);
  assert.deepEqual(mappings, [
    ...Array.from({length: 32}, (_, index) => ['root-' + index, 0, index]),
    ['profile', 1, -1], ['other', 2, -1],
  ]);
  assert.match(body, /^    needs: ci_policy$/m);
  assert.match(body, /^    timeout-minutes: 75$/m);
  assert.match(body, /^      fail-fast: false$/m);
  assert.doesNotMatch(body, /^    if:|max-parallel:|continue-on-error:/m);
  assert.match(step(body, 'Go test (race)'),
    /^        run: bash scripts\/test-module-ci\.sh race execute \$\{\{ matrix\.module-owner \}\} \$\{\{ matrix\.root-partition \}\}$/m);
}

function requireCompleteRaceDownloads(source) {
  const body = jobBody(source, 'module-completion');
  requireJobNeeds(source, 'module-completion', ['test', 'nested-cli', 'race', 'coverage', 'nested-cli-coverage']);
  assert.match(body, /^    if: \$\{\{ !cancelled\(\) \}\}$/m);
  assert.deepEqual([...body.matchAll(/^      - name: Download root part (\d+)$/gm)].map(match => Number(match[1])),
    Array.from({length: 32}, (_, index) => index));
  for (let index = 0; index < 32; index++) {
    const download = step(body, 'Download root part ' + index);
    assert.ok(download.includes('name: module-${{ matrix.flavor }}-${{ matrix.go-version }}-root-' + index + '\n'));
    assert.ok(download.includes('path: _out/module-${{ matrix.flavor }}-owners/owner-0000/part-' +
      String(index).padStart(4, '0') + '\n'));
    if (index >= 16) assert.match(download, /^        if: \$\{\{ !cancelled\(\) && matrix\.flavor == 'race' \}\}$/m);
    else assert.doesNotMatch(download, /^        if:.*matrix\.flavor/m);
  }
  assert.doesNotMatch(body, /merge-multiple:|pattern:/);
}

test('race owns 64 complete shards through 32 independent two-shard jobs', () => {
  requireRaceOwners(workflow);
});

test('complete aggregation retains every new race owner without raising budgets', () => {
  requireCompleteRaceDownloads(workflow);
});

test('race script selects its complete layout for execution and independent completion', () => {
  assert.match(script, /^root_partitions=16$/m);
  assert.match(script, /^shards=32$/m);
  assert.ok(script.includes('race) timeout=60m; flags=(-race); root_partitions=32; shards=64 ;;'));
  assert.equal([...script.matchAll(/-shards=\$shards -workers=2/g)].length, 2);
  assert.match(script, /GOMAXPROCS=2/);
  assert.match(script, /test\) timeout=45m ;;/);
  assert.match(script, /coverage\) timeout=45m; flags=\(-coverprofile=coverage-root\.out\) ;;/);
});

test('race layout rejects an omitted owner, four-shard owner, masked failure or incomplete readback', () => {
  requireRaceOwners(workflow);
  requireCompleteRaceDownloads(workflow);
  const race = jobBody(workflow, 'race');
  for (const [before, after] of [
    ['root-31,', ''],
    ['root-partition: 31', 'root-partition: 30'],
    ['timeout-minutes: 75', 'timeout-minutes: 90'],
    ['fail-fast: false', 'fail-fast: true'],
    ['timeout-minutes: 75', 'timeout-minutes: 75\n    continue-on-error: true'],
  ]) {
    const changed = race.replace(before, after);
    assert.notEqual(changed, race);
    assert.throws(() => requireRaceOwners(workflow.replace(race, () => changed)));
  }
  const complete = jobBody(workflow, 'module-completion');
  for (const index of [8, 16, 24, 31]) {
    const download = step(complete, 'Download root part ' + index);
    assert.throws(() => requireCompleteRaceDownloads(workflow.replace(download, '')));
  }
});
