'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {auditNativeOwners} = require('./audit-native-owners.cjs');

const roots = ['TestCrossLinuxRuntimeMatrixX86MMXStreamingOriginalAndLLVM'];
const children = ['original-go', 'llvm-default-O0', 'llvm-default-O2', 'llvm-O2-O0', 'llvm-O2-O2']
  .map(name => roots[0] + '/' + name);
const auditMMXStreaming = (inventory, raw) => auditNativeOwners(inventory, raw, roots, children);

module.exports = {auditMMXStreaming, roots, children};
if (require.main === module) {
  const directory = process.argv[2];
  const result = auditMMXStreaming(fs.readFileSync(path.join(directory, 'inventory.log'), 'utf8'),
    fs.readFileSync(path.join(directory, 'raw.jsonl'), 'utf8'));
  process.stdout.write(JSON.stringify(result) + '\n');
}
