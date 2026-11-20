'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const {auditNativeUnlocked, roots, children} = require('./audit-unlocked-native.cjs');

test('unlocked audit requires both executed ISAs and all three public API children', () => {
  assert.equal(roots.length, 2);
  assert.equal(children.length, 6);
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
  const encode = rows => rows.map(JSON.stringify).join('\n') + '\n';
  assert.deepEqual(auditNativeUnlocked(inventory, encode(events)),
    {roots: 2, children: 6, passed: 8, skipped: 0, incomplete: 0});
  for (const child of children) {
    for (const altered of [
      events.filter(row => row.Test !== child),
      events.map(row => row.Test === child && row.Action === 'pass' ? {...row, Action: 'skip'} : row),
      events.map(row => row.Test === child ? {...row, Test: child + '-object-only'} : row),
    ]) assert.throws(() => auditNativeUnlocked(inventory, encode(altered)));
  }
  assert.throws(() => auditNativeUnlocked(inventory,
    encode([event('start'), {...event('output'), Output: encode(events)}, event('pass')])));
});

test('unlocked native sources retain real host and backend requirements', () => {
  const native = fs.readFileSync('amd64_scalar_memory_rmw_linux_amd64_test.go', 'utf8');
  assert.equal((native.match(/x87IA32RequireNativeHost\(t\)/g) || []).length, 4);
  assert.equal((native.match(/\[\]string\{"-O0", "-O2"\}/g) || []).length, 2);
  assert.doesNotMatch(native, /\.Skip|qemu|rosetta|PLAN9ASM_CROSS_EXEC/);
});
