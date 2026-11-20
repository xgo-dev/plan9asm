'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const roots = ['TestCrossLinuxRuntimeMatrixX86LockScalarRMWNativeAMD64',
  'TestCrossLinuxRuntimeMatrixX86LockScalarRMWNative386'];

test('LOCK execution auditing requires original owners and all four completed backend children', () => {
  const {auditNativeLock, roots: actual, children} = require('./audit-lock-native.cjs');
  assert.deepEqual(actual, roots);
  assert.deepEqual(children, roots.flatMap(root => ['-O0', '-O2'].map(level => root + '/' + level)));
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
  const inventory = roots.join('\n') + '\n';
  const encode = values => values.map(JSON.stringify).join('\n') + '\n';
  assert.deepEqual(auditNativeLock(inventory, encode(events)),
    {roots: 2, children: 4, passed: 6, skipped: 0, incomplete: 0});
  for (const child of children) {
    for (const changed of [
      events.filter(value => value.Test !== child),
      events.filter(value => value.Test !== child || value.Action !== 'pass'),
      events.map(value => value.Test === child && value.Action === 'pass' ? {...value, Action: 'skip'} : value),
      events.map(value => value.Test === child ? {...value, Test: child + '-object-only'} : value),
    ]) assert.throws(() => auditNativeLock(inventory, encode(changed)));
  }
  for (const changed of [events.slice(0, -1), [...events, event('pass')],
    [event('start'), {...event('output'), Output: encode(events)}, event('pass')]]) {
    assert.throws(() => auditNativeLock(inventory, encode(changed)));
  }
});
