'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const path = require('node:path');
const {spawnSync} = require('node:child_process');

// Independent inventory for auditing historical diagnostic receipts.
const {qualifyDiagnosticNeeds} = require('./diagnostic-qualification.cjs');
const allNeeds = [
  'ownership', 'native-x86-oracles', 'sdk-priority', 'arm64-fallback-cross-priority',
  'lock-native-priority', 'unlocked-rmw-native-priority', 'vector-value-fault-priority',
  'packed-conversion-native-complete', 'packed-reduction-native-complete', 'complete-windows',
];

function successfulNeeds() {
  return Object.fromEntries(allNeeds.map(name => [name, {result: 'success', outputs: {}}]));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

test('only all ten genuine success results qualify; Windows cannot replace an original gate', () => {
  const {qualifyDiagnosticNeeds} = require('./diagnostic-qualification.cjs');
  assert.deepEqual(qualifyDiagnosticNeeds(successfulNeeds()), {schema: 1, successfulJobs: allNeeds});
  for (const name of allNeeds) {
    for (const result of ['failure', 'skipped', 'cancelled', 'queued', 'in_progress', '', true, null]) {
      const needs = successfulNeeds();
      needs[name].result = result;
      assert.throws(() => qualifyDiagnosticNeeds(needs), undefined, name + ': ' + result);
    }
    const missing = successfulNeeds();
    delete missing[name];
    assert.throws(() => qualifyDiagnosticNeeds(missing), undefined, 'missing ' + name);
    for (const malformed of [null, [], 'success', {outputs: {result: 'success'}}]) {
      const needs = successfulNeeds();
      needs[name] = malformed;
      assert.throws(() => qualifyDiagnosticNeeds(needs), undefined, 'malformed ' + name);
    }
  }
  for (const needs of [null, [], true, 'success', {},
    {...successfulNeeds(), extra: {result: 'success', outputs: {}}}]) {
    assert.throws(() => qualifyDiagnosticNeeds(needs));
  }
  const forged = clone(successfulNeeds());
  forged['native-x86-oracles'] = {result: 'failure', outputs: {result: 'success'}};
  forged['complete-windows'].outputs = {qualification: 'success'};
  assert.throws(() => qualifyDiagnosticNeeds(forged));
});

test('the actual qualification command exits nonzero for failed, skipped, absent or malformed needs', () => {
  const script = path.join(__dirname, 'diagnostic-qualification.cjs');
  const execute = input => {
    const env = {...process.env};
    if (input === undefined) delete env.DIAGNOSTIC_NEEDS_JSON;
    else env.DIAGNOSTIC_NEEDS_JSON = input;
    return spawnSync(process.execPath, [script], {encoding: 'utf8', timeout: 5000, env});
  };
  const rejects = (input, label) => {
    const failed = execute(input);
    assert.equal(failed.error, undefined, label);
    assert.equal(failed.signal, null, label);
    assert.ok(Number.isInteger(failed.status) && failed.status > 0, label);
    assert.equal(failed.stdout, '', label);
  };
  const success = execute(JSON.stringify(successfulNeeds()));
  assert.equal(success.error, undefined);
  assert.equal(success.status, 0, success.stderr);
  assert.deepEqual(JSON.parse(success.stdout), {schema: 1, successfulJobs: allNeeds});
  for (const name of allNeeds) {
    for (const result of ['failure', 'skipped', 'cancelled']) {
      const needs = successfulNeeds();
      needs[name].result = result;
      rejects(JSON.stringify(needs), name + ': ' + result);
    }
    const missing = successfulNeeds();
    delete missing[name];
    rejects(JSON.stringify(missing), 'missing ' + name);
  }
  for (const input of [undefined, '', '{', 'null', '[]', '{}']) {
    rejects(input, 'malformed actual context: ' + input);
  }
});

test('early Windows completion cannot qualify a pending failed or absent original owner', () => {
  const successful = () => Object.fromEntries(allNeeds.map(name => [name, {result: 'success', outputs: {}}]));
  assert.deepEqual(qualifyDiagnosticNeeds(successful()), {schema: 1, successfulJobs: allNeeds});
  for (const name of allNeeds) {
    for (const result of ['failure', 'cancelled', 'skipped', 'queued', 'in_progress']) {
      const changed = successful();
      changed[name] = {result, outputs: {result: 'success', qualification: 'success'}};
      assert.throws(() => qualifyDiagnosticNeeds(changed), undefined, name + '/' + result);
    }
    const changed = successful();
    delete changed[name];
    assert.throws(() => qualifyDiagnosticNeeds(changed), undefined, 'absent ' + name);
  }
});
