const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {auditNativeOwners} = require('./audit-native-owners.cjs');

const roots = ['TestCrossLinuxRuntimeMatrixX86LockScalarRMWNativeAMD64',
  'TestCrossLinuxRuntimeMatrixX86LockScalarRMWNative386'];
const children = roots.flatMap(root => ['-O0', '-O2'].map(level => root + '/' + level));
function auditNativeLock(inventory, raw) {
  return auditNativeOwners(inventory, raw, roots, children);
}
module.exports = {auditNativeLock, roots, children};

if (require.main === module) {
  assert.equal(process.argv.length, 3, 'one actual native LOCK report directory required');
  const directory = process.argv[2];
  const result = auditNativeLock(fs.readFileSync(path.join(directory, 'inventory.log'), 'utf8'),
    fs.readFileSync(path.join(directory, 'raw.jsonl'), 'utf8'));
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
}
