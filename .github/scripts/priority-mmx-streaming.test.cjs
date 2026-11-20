'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {auditMMXStreaming, roots, children} = require('./audit-mmx-streaming.cjs');

test('MMX streaming audit rejects omitted, skipped or substituted original/backend execution', () => {
  const event = (Action, Test) => ({Action, Package: 'github.com/xgo-dev/plan9asm', ...(Test ? {Test} : {})});
  const events = [event('start'), event('run', roots[0])];
  for (const child of children) events.push(event('run', child), event('pass', child));
  events.push(event('pass', roots[0]), event('pass'));
  const encode = values => values.map(JSON.stringify).join('\n') + '\n';
  assert.deepEqual(auditMMXStreaming(roots[0] + '\n', encode(events)),
    {roots:1, children:5, passed:6, skipped:0, incomplete:0});
  for (const child of children) {
    for (const changed of [
      events.filter(value => value.Test !== child),
      events.map(value => value.Test === child && value.Action === 'pass' ? {...value, Action:'skip'} : value),
      events.map(value => value.Test === child ? {...value, Test:child+'-object-only'} : value),
    ]) assert.throws(() => auditMMXStreaming(roots[0]+'\n', encode(changed)));
  }
  assert.throws(() => auditMMXStreaming('TestOtherOwner\n', encode(events)));
  assert.throws(() => auditMMXStreaming(roots[0]+'\n', encode([
    event('start'), {...event('output'), Output:'PASS '+children.join('\nPASS ')}, event('pass'),
  ])));
});
