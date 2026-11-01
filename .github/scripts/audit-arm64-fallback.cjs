const assert = require('node:assert/strict');
const fs = require('node:fs');

// The exhaustive runner separately verifies the complete source, tools, plan,
// commands and raw event protocol. This additional contract prevents removal
// of an execution child from silently shrinking this required runtime matrix.
function auditARM64Fallback(raw) {
  const root = 'TestFallbackARM64WideFrameCompilesWithLLVM22';
  const expected = [root, ...['darwin', 'linux', 'windows', 'native_complete-argument_oracle']
    .map(child => `${root}/${child}`)].sort();
  const started = new Set();
  const passed = new Set();
  let packagePassed = false;
  for (const line of raw.split(/\r?\n/).filter(Boolean)) {
    const event = JSON.parse(line);
    if (event.Action === 'build-output' && typeof event.ImportPath === 'string' && event.ImportPath && !event.Test) {
      continue;
    }
    assert.equal(event.Package, 'github.com/xgo-dev/plan9asm/cmd/plan9asmll');
    assert.ok(!packagePassed, 'event after package terminal');
    assert.ok(!['fail', 'skip', 'build-fail'].includes(event.Action), 'required execution did not pass');
    if (event.Action === 'run') {
      assert.ok(expected.includes(event.Test) && !started.has(event.Test), 'foreign or duplicate test');
      started.add(event.Test);
    }
    if (event.Action === 'pass') {
      if (event.Test) {
        assert.ok(started.has(event.Test) && !passed.has(event.Test), 'unstarted or duplicate terminal');
        passed.add(event.Test);
      } else {
        packagePassed = true;
      }
    }
  }
  assert.ok(packagePassed, 'package did not finish');
  assert.deepEqual([...started].sort(), expected, 'missing required execution axis');
  assert.deepEqual([...passed].sort(), expected, 'incomplete required execution axis');
  return { roots: 1, children: 4, passed: 5, skipped: 0, incomplete: 0 };
}

module.exports = { auditARM64Fallback };

if (require.main === module) {
  assert.equal(process.argv.length, 3, 'one original runner trace required');
  process.stdout.write(JSON.stringify(auditARM64Fallback(fs.readFileSync(process.argv[2], 'utf8')), null, 2) + '\n');
}
