'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {auditSSEAVXNativeFamilies} = require('./audit-duplicate-native-families.cjs');

const roots = [
  'TestCrossLinuxRuntimeMatrixX86ScalarReciprocalOriginalGoAndNativeAMD64',
  'TestCrossLinuxRuntimeMatrixX86ScalarReciprocalOriginalGoAndNative386',
];
const originalEvidence = 'actual original Go scalar estimates: 20 aliases × 24 bit patterns × 64 MXCSR profiles = 30720 whole32/FLAGS/DF/MXCSR/canary outcomes; independent scalar references, no AVX512/Z execution claim\n';

function pipelineEvidence(arch) {
  return `scalar estimates native arch=${arch} live=20 dead=4 whole32-outcomes=30720 fault-processes=40; SSE/AVX actual scalar opcodes, no AVX512/Z transport\n`;
}

function auditScalarReciprocalNative(inventory, raw) {
  return auditSSEAVXNativeFamilies(inventory, raw, roots, pipelineEvidence, originalEvidence);
}

module.exports = {auditScalarReciprocalNative};
if (require.main === module) {
  const directory = process.argv[2];
  const result = auditScalarReciprocalNative(fs.readFileSync(path.join(directory, 'inventory.log'), 'utf8'),
    fs.readFileSync(path.join(directory, 'raw.jsonl'), 'utf8'));
  process.stdout.write(JSON.stringify(result) + '\n');
}
