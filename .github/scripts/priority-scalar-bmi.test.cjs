'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {auditScalarBMI, roots} = require('./audit-scalar-bmi.cjs');

test('native scalar BMI execution cannot be replaced by skips, output text or an incomplete owner', () => {
  const event = (Action, Test) => ({Action, Package:'github.com/xgo-dev/plan9asm', ...(Test ? {Test} : {})});
  const events = [event('start'), ...roots.flatMap(root => [event('run', root), event('pass', root)]), event('pass')];
  const raw = values => values.map(JSON.stringify).join('\n') + '\n';
  const inventory = roots.join('\n') + '\n';
  assert.deepEqual(auditScalarBMI(inventory, raw(events)),
    {roots:3, children:0, passed:3, skipped:0, incomplete:0});
  for (const root of roots) {
    assert.throws(() => auditScalarBMI(inventory, raw(events.filter(event => event.Test !== root))));
    assert.throws(() => auditScalarBMI(inventory, raw(events.map(event =>
      event.Test === root && event.Action === 'pass' ? {...event, Action:'skip'} : event))));
  }
  assert.throws(() => auditScalarBMI(inventory, raw(events.slice(0, -1))));
  assert.throws(() => auditScalarBMI(inventory,
    raw([event('start'), {...event('output'), Output:roots.join('\nPASS ')}, event('pass')])));
});
