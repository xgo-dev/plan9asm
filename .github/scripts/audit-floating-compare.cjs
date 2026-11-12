'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {auditNativeOwners} = require('./audit-native-owners.cjs');

const roots = [
  'TestCrossLinuxRuntimeMatrixX86FloatingCompareIndependentIEEEAndMXCSR',
  'TestCrossLinuxRuntimeMatrixX86FloatingCompareDeadResultEffects',
  'TestCrossLinuxRuntimeMatrixX86FloatingCompareFPScalarByteSpans',
  'TestCrossLinuxRuntimeMatrixX86FloatingCompareLegacyUpperAliases',
];
const children = [
  ...['CMPPS', 'CMPPD', 'CMPSS', 'CMPSD'].map(opcode => roots[0] + '/' + opcode),
  ...['-O0', '-O2'].map(level => roots[1] + '/' + level),
];
const auditFloatingCompare = (inventory, raw) => auditNativeOwners(inventory, raw, roots, children);

module.exports = {auditFloatingCompare, roots, children};
if (require.main === module) {
  const directory = process.argv[2];
  const result = auditFloatingCompare(fs.readFileSync(path.join(directory, 'inventory.log'), 'utf8'),
    fs.readFileSync(path.join(directory, 'raw.jsonl'), 'utf8'));
  process.stdout.write(JSON.stringify(result) + '\n');
}
