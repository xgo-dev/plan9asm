const assert = require('node:assert/strict');

// The caller supplies a fixed first-party inventory, never report metadata.
// Printed payloads and incomplete, duplicated or skipped test axes are not runs.
function auditNativeOwners(inventory, raw, roots, children) {
  assert.ok(roots.length > 0, 'required native owners cannot be empty');
  assert.equal(new Set(roots).size, roots.length, 'duplicate required native owner');
  assert.ok(roots.every(root => /^Test[^/\s]+$/.test(root)), 'invalid required native owner');
  assert.ok(children.every(child => roots.some(root => child.startsWith(root + '/'))),
    'required native child has no owner');
  const discovered = inventory.split(/\r?\n/).filter(line => line.startsWith('Test'));
  assert.deepEqual(discovered.slice().sort(), roots.slice().sort(), 'complete fresh native inventory changed');
  const expected = new Set([...roots, ...children]);
  assert.equal(expected.size, roots.length + children.length, 'duplicate required native axis');
  const started = new Set(), passed = new Set();
  let complete = false;
  for (const line of raw.split(/\r?\n/).filter(Boolean)) {
    const event = JSON.parse(line);
    if (event.Action === 'build-output' && typeof event.ImportPath === 'string' && event.ImportPath && !event.Test) continue;
    assert.equal(event.Package, 'github.com/xgo-dev/plan9asm', 'foreign native package');
    assert.ok(!complete, 'event after native package terminal');
    assert.ok(!['fail', 'skip', 'build-fail'].includes(event.Action), 'required native execution failed or skipped');
    if (event.Test) {
      const owner = event.Test.split('/')[0];
      assert.ok(expected.has(event.Test), 'foreign native root or hardware/ABI/backend child');
      if (event.Test !== owner) assert.ok(started.has(owner) && !passed.has(owner), 'child outside its live owner');
      for (const parent of expected) {
        if (event.Test.startsWith(parent + '/')) {
          assert.ok(started.has(parent) && !passed.has(parent), 'child outside a required live architecture parent');
        }
      }
      if (event.Action === 'run') {
        assert.ok(!started.has(event.Test), 'duplicate native start');
        started.add(event.Test);
      } else {
        assert.ok(started.has(event.Test), 'event for an unstarted native owner');
        if (event.Action === 'pass') {
          assert.ok(!passed.has(event.Test), 'duplicate native terminal');
          passed.add(event.Test);
        }
      }
    } else if (event.Action === 'pass') {
      assert.deepEqual([...started].sort(), [...expected].sort(), 'missing native execution axis');
      assert.deepEqual([...passed].sort(), [...expected].sort(), 'unfinished native execution axis');
      complete = true;
    }
  }
  assert.ok(complete, 'native package did not finish successfully');
  return {roots: roots.length, children: children.length, passed: passed.size, skipped: 0, incomplete: 0};
}

module.exports = {auditNativeOwners};
