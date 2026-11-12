'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {auditProductCMOV, roots, children} = require('./audit-product-cmov.cjs');

test('product and CMOV execution retains every root and optimization child without skips', () => {
  assert.deepEqual(roots, [
    'TestCrossLinuxRuntimeMatrixX86DwordProductIndependentWholeBytes',
    'TestCrossLinuxRuntimeMatrixX86CMOVIndependentWholeBytes',
    'TestCrossLinuxRuntimeMatrixX86AESFamilyWholeByteAliases',
    'TestAMD64VectorTestRuntimeSemantics',
    'TestAMD64IFMARuntimeSemantics',
    'TestAMD64QwordBitLookupRuntimeSemantics',
    'TestCrossLinuxRuntimeMatrixX86CMOVFPPartialCrossSlotWholeBytes',
  ]);
  const event = (Action, Test) => ({Action, Package: 'github.com/xgo-dev/plan9asm', ...(Test ? {Test} : {})});
  const events = [event('start')];
  for (const root of roots) {
    events.push(event('run', root));
    for (const child of children.filter(name => name.startsWith(root + '/'))) {
      events.push(event('run', child), event('pass', child));
    }
    events.push(event('pass', root));
  }
  events.push(event('pass'));
  const raw = values => values.map(JSON.stringify).join('\n') + '\n';
  const inventory = roots.join('\n') + '\n';
  assert.deepEqual(auditProductCMOV(inventory, raw(events)),
    {roots: 7, children: 24, passed: 31, skipped: 0, incomplete: 0});
  for (const name of [...roots, ...children]) {
    assert.throws(() => auditProductCMOV(inventory, raw(events.filter(event => event.Test !== name))));
    for (const Action of ['skip', 'fail']) {
      assert.throws(() => auditProductCMOV(inventory, raw(events.map(event =>
        event.Test === name && event.Action === 'pass' ? {...event, Action} : event))));
    }
  }
  assert.throws(() => auditProductCMOV(inventory, raw(events.slice(0, -1))));
  assert.throws(() => auditProductCMOV(inventory, raw([event('start'), event('pass')])));
});
