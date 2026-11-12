'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {auditNativeOwners} = require('./audit-native-owners.cjs');

const roots = [
  'TestAMD64GetExpRuntimeSemantics',
  'TestAMD64GetMantRuntimeSemantics',
  'TestAMD64ScaleFRuntimeSemantics',
  'TestAMD64FloatingRangeRuntimeSemantics',
  'TestAMD64FloatingRangeDoubleAndScalarRuntimeSemantics',
  'TestAMD64FixupImmediateRuntimeSemantics',
  'TestAMD64ScaledRoundRuntimeSemantics',
  'TestAMD64FPClassRuntimeSemantics',
];
const axes = ['backend_O0', 'backend_O2', 'IR_O2/backend_O2'];
const children = roots.flatMap(root => axes.map(axis => root + '/' + axis));

function auditFloatingHelpers(inventory, raw) {
  const result = auditNativeOwners(inventory, raw, roots, children);
  const output = new Map(roots.map(root => [root, '']));
  const preflights = new Set();
  for (const line of raw.split(/\r?\n/).filter(Boolean)) {
    const event = JSON.parse(line);
    if (event.Action === 'output' && output.has(event.Test)) {
      output.set(event.Test, output.get(event.Test) + event.Output);
    }
    if (event.Action !== 'run' || !children.includes(event.Test)) continue;
    const root = event.Test.split('/')[0];
    const observation = output.get(root);
    const flags = observation.match(/AVX512F=1 AVX512DQ=1 AVX512VL=1 OSXSAVE=1 XCR0=([0-9a-f]+)\b/);
    assert.ok(flags, 'missing current native F/DQ/VL and OS-enabled state: ' + root);
    assert.equal(BigInt('0x' + flags[1]) & 0xe6n, 0xe6n, 'incomplete native XCR0: ' + root);
    assert.ok(observation.includes('FLOATING_HELPER_NATIVE_DQ_OK'),
      'original native DQ opcode did not complete before its runtime: ' + root);
    preflights.add(root);
  }
  assert.equal(preflights.size, 8, 'missing actual native floating-helper preflight');
  return {...result, preflights: preflights.size};
}

module.exports = {auditFloatingHelpers, roots, children};
if (require.main === module) {
  const directory = process.argv[2];
  const result = auditFloatingHelpers(fs.readFileSync(path.join(directory, 'inventory.log'), 'utf8'),
    fs.readFileSync(path.join(directory, 'raw.jsonl'), 'utf8'));
  process.stdout.write(JSON.stringify(result) + '\n');
}
