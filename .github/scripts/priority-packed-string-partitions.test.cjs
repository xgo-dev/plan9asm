'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../../amd64_packed_string_vector_test.go'), 'utf8');

for (const [name, arch, triple] of [
  ['Linux386', '386', 'i386-unknown-linux-gnu'],
  ['Windows386', '386', 'i686-pc-windows-msvc'],
  ['DarwinAMD64', 'amd64', 'x86_64-apple-darwin'],
  ['LinuxAMD64', 'amd64', 'x86_64-unknown-linux-gnu'],
  ['WindowsAMD64', 'amd64', 'x86_64-pc-windows-msvc'],
]) {
  test('packed-string objects retain independent complete owner ' + name, () => {
    const declaration = `func TestX86PackedStringObjects${name}(t *testing.T) {\n` +
      `\tx86PackedStringTargetObjects(t, "${arch}", "${triple}")\n}`;
    assert.ok(source.includes(declaration), 'missing independent target owner');
  });
}

test('packed-string partitioning retains every original row and object axis', () => {
  assert.ok(source.includes('func TestX86PackedStringObjectBatchInventory(t *testing.T)'));
  assert.ok(!source.includes('func TestX86PackedStringThreeAPIsFiveTargetsO0O2Objects('));
  assert.ok(source.includes('const maxFunctions = 64'));
  assert.ok(source.includes('reflect.DeepEqual(joined, original)'));
  const helper = source.slice(source.indexOf('func x86PackedStringTargetObjects('),
    source.indexOf('\nfunc TestX86PackedStringObjectsLinux386('));
  assert.ok(helper.startsWith('func x86PackedStringTargetObjects('));
  assert.ok(helper.includes('x86PackedStringObjectBatches(x86PackedStringVectorCases())'));
  assert.ok(helper.includes('[]string{"text", "module", "Go"}'));
  assert.ok(helper.includes('[]string{"-O0", "-O2"}'));
  assert.ok(helper.includes('x86LEAActualTargetGoObject(t, arch, triple, source)'));
  assert.ok(helper.includes('input = x86UndefinedTrapOptimizedIR(t, input)'));
  assert.ok(helper.includes('x86PackedStringCompileObject(t, llc, triple, input, level)'));
  assert.ok(!helper.includes('t.Skip'));
});
