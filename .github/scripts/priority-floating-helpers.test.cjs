'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {auditFloatingHelpers} = require('./audit-floating-helpers.cjs');

// Keep this denominator independent of the implementation/auditor exports.
const owners = [
  'TestAMD64GetExpRuntimeSemantics',
  'TestAMD64GetMantRuntimeSemantics',
  'TestAMD64ScaleFRuntimeSemantics',
  'TestAMD64FloatingRangeRuntimeSemantics',
  'TestAMD64FloatingRangeDoubleAndScalarRuntimeSemantics',
  'TestAMD64FixupImmediateRuntimeSemantics',
  'TestAMD64ScaledRoundRuntimeSemantics',
  'TestAMD64FPClassRuntimeSemantics',
];
const axes = ['backend_O0', 'backend_O2', 'IR_O2/backend_O2'];
const packageName = 'github.com/xgo-dev/plan9asm';
const event = (Action, Test, Output) => ({Action, Package: packageName,
  ...(Test ? {Test} : {}), ...(Output ? {Output} : {})});
const inventory = owners.join('\n') + '\nok\t' + packageName + '\n';
const native = 'AVX512F=1 AVX512DQ=1 AVX512VL=1 OSXSAVE=1 XCR0=e7\nFLOATING_HELPER_NATIVE_DQ_OK\n';

function completeEvents() {
  const events = [event('start')];
  for (const owner of owners) {
    events.push(event('run', owner), event('output', owner, native));
    for (const axis of axes) {
      events.push(event('run', owner + '/' + axis), event('pass', owner + '/' + axis));
    }
    events.push(event('pass', owner));
  }
  events.push(event('pass'));
  return events;
}
const serialize = events => events.map(value => JSON.stringify(value)).join('\n');

test('native helper audit requires all eight originals and 24 execution children', () => {
  assert.deepEqual(auditFloatingHelpers(inventory, serialize(completeEvents())),
    {roots: 8, children: 24, passed: 32, skipped: 0, incomplete: 0, preflights: 8});
});

test('native helper audit rejects every absent, failed, skipped or incomplete owner/axis', () => {
  const expected = owners.flatMap(owner => [owner, ...axes.map(axis => owner + '/' + axis)]);
  for (const name of expected) {
    const original = completeEvents();
    for (const action of ['fail', 'skip']) {
      const changed = original.map(value => value.Action === 'pass' && value.Test === name
        ? {...value, Action: action} : value);
      assert.throws(() => auditFloatingHelpers(inventory, serialize(changed)), name + '/' + action);
    }
    assert.throws(() => auditFloatingHelpers(inventory,
      serialize(original.filter(value => value.Test !== name))), 'missing ' + name);
    assert.throws(() => auditFloatingHelpers(inventory,
      serialize(original.filter(value => value.Action !== 'pass' || value.Test !== name))), 'unfinished ' + name);
    const started = original.find(value => value.Action === 'run' && value.Test === name);
    assert.throws(() => auditFloatingHelpers(inventory,
      serialize([started, ...original])), 'duplicate ' + name);
  }
});

test('native helper audit rejects missing, late or incomplete actual CPU/opcode preflight', () => {
  for (const owner of owners) {
    for (const text of ['', native.replace('DQ=1', 'DQ=0'), native.replace('F=1', 'F=0'),
      native.replace('VL=1', 'VL=0'), native.replace('OSXSAVE=1', 'OSXSAVE=0'),
      native.replace('XCR0=e7', 'XCR0=7'), native.replace('FLOATING_HELPER_NATIVE_DQ_OK', 'object-only')]) {
      const changed = completeEvents().map(value => value.Action === 'output' && value.Test === owner
        ? {...value, Output: text} : value);
      assert.throws(() => auditFloatingHelpers(inventory, serialize(changed)), owner);
    }
    const changed = completeEvents();
    const at = changed.findIndex(value => value.Action === 'output' && value.Test === owner);
    const [late] = changed.splice(at, 1);
    changed.splice(at + 2, 0, late);
    assert.throws(() => auditFloatingHelpers(inventory, serialize(changed)), 'late ' + owner);
  }
});

test('native helper audit rejects changed inventories, foreign paths and printed success', () => {
  for (const changed of ['', inventory + owners[0] + '\n', inventory.replace(owners[0] + '\n', '')]) {
    assert.throws(() => auditFloatingHelpers(changed, serialize(completeEvents())));
  }
  for (const changed of [
    [event('output', undefined, '32 passed')],
    completeEvents().slice(0, -1),
    [event('run', owners[0] + '/sample'), ...completeEvents()],
    [...completeEvents(), event('pass')],
  ]) assert.throws(() => auditFloatingHelpers(inventory, serialize(changed)));
});
