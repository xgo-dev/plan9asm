'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {auditNativeOwners} = require('./audit-native-owners.cjs');

// These execute portable LLVM memory semantics on a real Linux host. They do
// not claim original-Go or physical AVX512 instruction execution.
const roots = ['TestX86VectorValueNativePortableFaults', 'TestGoX86NumericalSBReadRuntimeFaultCorePolicy'];
const children = ['text', 'module', 'Go'].map(api => roots[0]+'/'+api)
  .concat(['386/mutable', '386/width', 'amd64/mutable', 'amd64/width', 'amd64/local']
    .map(role => roots[1]+'/'+role));

function auditValueFaultPriority(inventory, raw) {
  return auditNativeOwners(inventory, raw, roots, children);
}

module.exports = {auditValueFaultPriority, roots, children};

if (require.main === module) {
  assert.equal(process.argv.length, 3, 'one actual portable fault report directory required');
  const directory = process.argv[2];
  const result = auditValueFaultPriority(fs.readFileSync(path.join(directory, 'inventory.log'), 'utf8'),
    fs.readFileSync(path.join(directory, 'raw.jsonl'), 'utf8'));
  process.stdout.write(JSON.stringify(result, null, 2)+'\n');
}
