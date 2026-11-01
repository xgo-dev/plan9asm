const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {auditNativeOwners} = require('./audit-native-owners.cjs');

const roots = [
  'TestCrossLinuxRuntimeMatrixX86X87SignedI64IdentityOriginalGoAndLLVM',
  'TestAMD64X87ConditionalMoveRuntimeConditions',
  'TestX86RawX87ClearExceptionRuntimeSemantics',
  'TestX86RawX87SoftwareClearPreservesAllStatusFields',
  'TestCrossLinuxRuntimeMatrixX86X87ScopedRoundingOriginalGoAndLLVM',
];
const children = [];
for (const arch of ['amd64', '386']) {
  const parent = `${roots[0]}/${arch}`;
  children.push(parent);
  for (const api of ['text', 'module', 'Go']) {
    for (const optimized of [false, true]) {
      for (const backend of [0, 2]) children.push(`${parent}/${api}/IR_O2=${optimized}/backend-O${backend}`);
    }
  }
}
for (const api of ['text', 'module', 'Go']) {
  const parent = `${roots[4]}/${api}`;
  children.push(parent);
  for (const optimized of [false, true]) {
    for (const backend of [0, 2]) children.push(`${parent}/IR_O2=${optimized}/backend-O${backend}`);
  }
}

function auditNativeX87(inventory, raw) {
  return auditNativeOwners(inventory, raw, roots, children);
}

module.exports = {auditNativeX87, roots, children};

if (require.main === module) {
  assert.equal(process.argv.length, 3, 'one actual native x87 report directory required');
  const directory = process.argv[2];
  const result = auditNativeX87(fs.readFileSync(path.join(directory, 'inventory.log'), 'utf8'),
    fs.readFileSync(path.join(directory, 'raw.jsonl'), 'utf8'));
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
}
