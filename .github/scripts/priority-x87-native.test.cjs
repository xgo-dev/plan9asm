const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');

const roots = [
  'TestCrossLinuxRuntimeMatrixX86X87SignedI64IdentityOriginalGoAndLLVM',
  'TestAMD64X87ConditionalMoveRuntimeConditions',
  'TestX86RawX87ClearExceptionRuntimeSemantics',
  'TestX86RawX87SoftwareClearPreservesAllStatusFields',
  'TestCrossLinuxRuntimeMatrixX86X87ScopedRoundingOriginalGoAndLLVM',
];

test('native x87 auditor requires actual complete ordered terminals, not printed PASS text', () => {
  const {auditNativeX87, roots: actualRoots, children} = require('./audit-x87-native.cjs');
  assert.deepEqual(actualRoots, roots);
  const originalChildren = [];
  for (const arch of ['amd64', '386']) {
    const parent = `${roots[0]}/${arch}`;
    originalChildren.push(parent);
    for (const api of ['text', 'module', 'Go']) {
      for (const optimized of [false, true]) {
        for (const backend of [0, 2]) originalChildren.push(`${parent}/${api}/IR_O2=${optimized}/backend-O${backend}`);
      }
    }
  }
  const roundingChildren = [];
  for (const api of ['text', 'module', 'Go']) {
    const parent = `${roots[4]}/${api}`;
    roundingChildren.push(parent);
    for (const optimized of [false, true]) {
      for (const backend of [0, 2]) roundingChildren.push(`${parent}/IR_O2=${optimized}/backend-O${backend}`);
    }
  }
  assert.equal(originalChildren.length, 26, 'retain all original native axes');
  assert.equal(roundingChildren.length, 15, 'three rounding API parents and twelve complete pipelines');
  assert.deepEqual(children, [...originalChildren, ...roundingChildren]);
  const event = (Action, Test) => ({Action, Package: 'github.com/xgo-dev/plan9asm', ...(Test ? {Test} : {})});
  const events = [event('start')];
  for (const root of roots) {
    events.push(event('run', root));
    for (const parent of children.filter(name => name.startsWith(root + '/') && name.split('/').length === 2)) {
      events.push(event('run', parent));
      for (const child of children.filter(name => name.startsWith(parent + '/'))) {
        events.push(event('run', child), event('pass', child));
      }
      events.push(event('pass', parent));
    }
    events.push(event('pass', root));
  }
  events.push(event('pass'));
  const inventory = roots.join('\n') + '\nok\tgithub.com/xgo-dev/plan9asm\n';
  const encode = values => values.map(value => JSON.stringify(value)).join('\n') + '\n';
  assert.deepEqual(auditNativeX87(inventory, encode(events)), {roots: 5, children: 41, passed: 46, skipped: 0, incomplete: 0});
  const child = children[1];
  const earlyParent = events.filter(value => value.Test !== children[0] || value.Action !== 'pass');
  earlyParent.splice(earlyParent.findIndex(value => value.Test === child), 0, event('pass', children[0]));
  for (const changed of [
    earlyParent,
    events.filter(value => value.Test !== child),
    events.filter(value => value.Test !== child || value.Action !== 'pass'),
    events.map(value => value.Test === child && value.Action === 'pass' ? {...value, Action: 'skip'} : value),
    events.map(value => value.Test === child && value.Action === 'pass' ? {...value, Action: 'fail'} : value),
    events.map(value => value.Test === child ? {...value, Test: child + '-object-only'} : value),
    events.slice(0, -1),
    [...events, event('pass')],
    [event('start'), {...event('output'), Output: events.map(value => 'PASS ' + (value.Test || 'package')).join('\n')}, event('pass')],
  ]) assert.throws(() => auditNativeX87(inventory, encode(changed)));
  for (const child of roundingChildren) {
    for (const action of ['skip', 'fail']) {
      assert.throws(() => auditNativeX87(inventory, encode(events.map(value =>
        value.Test === child && value.Action === 'pass' ? {...value, Action: action} : value))));
    }
    assert.throws(() => auditNativeX87(inventory, encode(events.filter(value => value.Test !== child))));
    assert.throws(() => auditNativeX87(inventory, encode(events.filter(value =>
      value.Test !== child || value.Action !== 'pass'))));
  }
  assert.throws(() => auditNativeX87(inventory.replace(roots[0], 'TestObjectOnly'), encode(events)));
});

test('scoped rounding emits explicit live API parents for all twelve native pipelines', () => {
  const source = fs.readFileSync('x86_x87_scoped_rounding_linux_amd64_test.go', 'utf8');
  assert.match(source, /func TestCrossLinuxRuntimeMatrixX86X87ScopedRoundingOriginalGoAndLLVM\(t \*testing\.T\)/);
  assert.match(source, /for _, api := range \[\]string\{"text", "module", "Go"\} \{\n\s+t\.Run\(api, func\(t \*testing\.T\) \{/);
  assert.match(source, /t\.Run\(fmt\.Sprintf\("IR_O2=%t\/backend%s", optimized, level\)/);
  assert.doesNotMatch(source, /t\.Skip|exec\.Command|qemu|rosetta/);
});
