'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {auditFloatingCompare, roots, children} = require('./audit-floating-compare.cjs');

test('floating execution auditing retains all result, dead, FP-field, alias and backend owners', () => {
  const event = (Action, Test) => ({Action, Package: 'github.com/xgo-dev/plan9asm', ...(Test ? {Test} : {})});
  const events = [event('start')];
  for (const root of roots) {
    events.push(event('run', root));
    for (const child of children.filter(child => child.startsWith(root + '/'))) {
      events.push(event('run', child), event('pass', child));
    }
    events.push(event('pass', root));
  }
  events.push(event('pass'));
  const raw = values => values.map(JSON.stringify).join('\n') + '\n';
  const inventory = roots.join('\n') + '\n';
  assert.deepEqual(auditFloatingCompare(inventory, raw(events)),
    {roots:4, children:6, passed:10, skipped:0, incomplete:0});
  for (const name of [...roots, ...children]) {
    assert.throws(() => auditFloatingCompare(inventory, raw(events.filter(event => event.Test !== name))));
    assert.throws(() => auditFloatingCompare(inventory, raw(events.map(event =>
      event.Test === name && event.Action === 'pass' ? {...event, Action:'skip'} : event))));
    assert.throws(() => auditFloatingCompare(inventory, raw(events.map(event =>
      event.Test === name ? {...event, Test:name+'-compile-only'} : event))));
  }
  assert.throws(() => auditFloatingCompare(roots.slice(1).join('\n')+'\n', raw(events)));
  assert.throws(() => auditFloatingCompare(inventory, raw([
    event('start'), {...event('output'), Output:'PASS '+roots.join('\nPASS ')}, event('pass'),
  ])));
});
