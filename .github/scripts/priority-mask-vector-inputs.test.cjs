'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

test('portable fault audit requires both actual owners and every completed child', () => {
  const {auditValueFaultPriority, roots, children} = require('./audit-value-fault-priority.cjs');
  const event = (Action, Test) => ({Action, Package: 'github.com/xgo-dev/plan9asm', ...(Test ? {Test} : {})});
  const events = [event('start')];
  for (const root of roots) {
    events.push(event('run', root));
    for (const child of children.filter(child => child.startsWith(root+'/'))) {
      events.push(event('run', child), event('pass', child));
    }
    events.push(event('pass', root));
  }
  events.push(event('pass'));
  const inventory = roots.join('\n')+'\nok\tgithub.com/xgo-dev/plan9asm\n';
  const encode = values => values.map(value => JSON.stringify(value)).join('\n')+'\n';
  assert.deepEqual(auditValueFaultPriority(inventory, encode(events)),
    {roots:2, children:8, passed:10, skipped:0, incomplete:0});
  for (const changed of [
    events.filter(value => value.Test !== children[0]),
    events.filter(value => value.Test !== children[0] || value.Action !== 'pass'),
    events.map(value => value.Test === children[0] && value.Action === 'pass' ? {...value, Action:'skip'} : value),
    events.map(value => value.Test === children[0] && value.Action === 'pass' ? {...value, Action:'fail'} : value),
    events.map(value => value.Test === children[0] ? {...value, Test:children[0]+'/sample'} : value),
    events.slice(0,-1),
    [...events, event('pass')],
    [event('start'), {...event('output'), Output:'PASS '+children.join('\nPASS ')}, event('pass')],
  ]) assert.throws(() => auditValueFaultPriority(inventory, encode(changed)));
  assert.throws(() => auditValueFaultPriority(inventory.replace(roots[0], 'TestUnrelatedOwner'), encode(events)));
});
