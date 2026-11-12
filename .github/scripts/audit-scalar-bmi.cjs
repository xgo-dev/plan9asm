'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {auditNativeOwners} = require('./audit-native-owners.cjs');

const roots = [
  'TestAMD64BLSRuntimeSemantics',
  'TestAMD64BEXTRRuntimeSemanticsAndFlags',
  'TestAMD64BZHIRuntimeSemanticsAndFlags',
];
const auditScalarBMI = (inventory, raw) => auditNativeOwners(inventory, raw, roots, []);

module.exports = {auditScalarBMI, roots};
if (require.main === module) {
  const directory = process.argv[2];
  const result = auditScalarBMI(fs.readFileSync(path.join(directory, 'inventory.log'), 'utf8'),
    fs.readFileSync(path.join(directory, 'raw.jsonl'), 'utf8'));
  process.stdout.write(JSON.stringify(result) + '\n');
}
