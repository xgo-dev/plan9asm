const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

function auditNativePriority(directory, io = fs) {
  const inventories = {
    'static-read': ['TestX86RawReturnStaticReadNumericOracle'],
    alias: [
      'TestCrossLinuxRuntimeMatrixX86MOVQSourceAliasesOriginalAndLLVM',
      'TestCrossLinuxRuntimeMatrixX86MOVQSourceAliasesCountedProvenance',
    ],
    bool: [
      'TestCrossLinuxRuntimeMatrixAMD64RegisterCanonicalBoolInstructionBytes',
      'TestCrossLinuxRuntimeMatrixGoAMD64CanonicalBoolByteRepresentation',
    ],
    caller: [
      'TestCrossLinuxRuntimeMatrixX86CallerAddressInstructionBytesAndLLVM',
      'TestCrossLinuxRuntimeMatrixGoX86CallerAddressABI0Representation',
    ],
    'caller-cmp': [
      'TestCrossLinuxRuntimeMatrixX86CallerAddressCMPInstructionBytesAndLLVM',
      'TestCrossLinuxRuntimeMatrixGoX86CallerAddressCMPABI0Representation',
    ],
    numerical: [
      'TestCrossLinuxRuntimeMatrixX86NumericalSBReadMutableAMD64',
      'TestCrossLinuxRuntimeMatrixX86NumericalSBReadMutableLocalAMD64',
    ],
    'numerical-lea': ['TestCrossLinuxRuntimeMatrixX86NumericalLEAOriginalBytesAndLLVM'],
    'direct-tail': [
      'TestCrossLinuxRuntimeMatrixAMD64DirectTailWholeSourceOriginalGoAndLLVM',
      'TestCrossLinuxRuntimeMatrixX86DirectTail386OriginalGoAndLLVM',
      'TestCrossLinuxRuntimeMatrixX86DirectTailPCResultAliasesAndExternal',
    ],
    'gp-simd-sparse': [
      'TestCrossLinuxRuntimeMatrixX86GPSIMDSparseNativeAMD64OriginalGoAndLLVM',
      'TestCrossLinuxRuntimeMatrixX86GPSIMDSparseNative386OriginalGoAndLLVM',
    ],
    'bit-scan': [
      'TestCrossLinuxRuntimeMatrixX86BitScanNativeAMD64OriginalGoAndLLVM',
      'TestCrossLinuxRuntimeMatrixX86BitScanNative386OriginalGoAndLLVM',
    ],
    'bool-386': ['TestCrossLinuxRuntimeMatrixX86ABI0Mode32CanonicalBoolOriginalGoAndLLVM'],
    'packed-string': ['TestCrossLinuxRuntimeMatrixX86PackedStringImplicitVectorNativeAVX'],
    'independent-fp': [
      'TestCrossLinuxRuntimeMatrixX86InsertExtractIndependentFPFields',
      'TestCrossLinuxRuntimeMatrixX86LegacyPSIndependentFPFields',
    ],
    'source-stack': ['TestCrossLinuxRuntimeMatrixX86RawSourceStackNumerical'],
    continuation: ['TestCrossLinuxRuntimeMatrixX86ContinuationWholeCFGOriginalGoAndLLVM'],
    'packed-string-fault': ['TestCrossLinuxRuntimeMatrixX86PackedStringOriginalNativeMemoryFaults'],
    'byte-swap': ['TestCrossLinuxRuntimeMatrixX86ByteSwapOriginalGoAndLLVM'],
    crc32: ['TestAMD64CRC32RuntimeSemanticsAndFlags'],
    'bit-test': ['TestCrossLinuxRuntimeMatrixX86BitTestNumericalAndAliases'],
  };
  const actualFiles = io.readdirSync(directory).filter(name => name.endsWith('-inventory.log')).sort();
  assert.deepEqual(actualFiles, Object.keys(inventories).map(name => name + '-inventory.log').sort(),
    'missing or foreign independent native-axis inventories');
  const mandatory = new Set();
  for (const [inventory, expected] of Object.entries(inventories)) {
    const names = io.readFileSync(path.join(directory, inventory + '-inventory.log'), 'utf8')
      .split(/\r?\n/).filter(line => /^Test\S+$/.test(line));
    assert.deepEqual(names.slice().sort(), expected.slice().sort(), 'changed mandatory inventory: ' + inventory);
    for (const name of names) {
      assert.ok(!mandatory.has(name), 'duplicate mandatory owner: ' + name);
      mandatory.add(name);
    }
  }
  assert.equal(mandatory.size, 29);
  const discovered = io.readFileSync(path.join(directory, 'all-roots.stdout'), 'utf8')
    .split(/\r?\n/).filter(line => /^Test\S+$/.test(line)).sort();
  assert.equal(discovered.length, 66, 'fresh discovery denominator changed');
  assert.equal(new Set(discovered).size, 66, 'duplicate fresh discovery');
  const roots = new Set(), rootTerminals = new Set();
  const children = new Set(), childTerminals = new Set();
  let packageTerminal;
  io.readFileSync(path.join(directory, 'native.stderr'), 'utf8');
  const raw = io.readFileSync(path.join(directory, 'native.jsonl'), 'utf8');
  for (const line of raw.split(/\r?\n/)) {
    if (!line) continue;
    const event = JSON.parse(line);
    if (event.Package) assert.equal(event.Package, 'github.com/xgo-dev/plan9asm', 'foreign package event');
    if (!event.Test) {
      assert.notEqual(event.Action, 'build-fail', 'native package build failed');
      if (['pass', 'fail', 'skip'].includes(event.Action)) {
        assert.equal(event.Package, 'github.com/xgo-dev/plan9asm', 'package terminal lacks exact package identity');
        assert.equal(packageTerminal, undefined, 'duplicate package terminal');
        assert.equal(event.Action, 'pass', 'native package did not execute successfully');
        packageTerminal = { package: event.Package, elapsed: event.Elapsed };
      }
      continue;
    }
    assert.equal(packageTerminal, undefined, 'test event after package terminal');
    assert.equal(event.Package, 'github.com/xgo-dev/plan9asm', 'test lacks exact package identity');
    const child = event.Test.includes('/');
    const root = event.Test.split('/')[0];
    const starts = child ? children : roots;
    const terminals = child ? childTerminals : rootTerminals;
    if (child) assert.ok(roots.has(root), 'foreign/unstarted child root: ' + event.Test);
    if (event.Action === 'run') {
      assert.ok(!starts.has(event.Test), 'duplicate test start: ' + event.Test);
      if (child) {
        // t.Run may put slashes in one literal name without intermediate
        // parent events. The actual root must still have started.
        assert.ok(!rootTerminals.has(root), 'child starts after root terminal');
      }
      starts.add(event.Test);
    }
    if (['pass', 'fail', 'skip'].includes(event.Action)) {
      assert.ok(starts.has(event.Test), 'test terminal lacks start: ' + event.Test);
      assert.ok(!terminals.has(event.Test), 'duplicate test terminal: ' + event.Test);
      if (child) assert.ok(!rootTerminals.has(root), 'child finishes after root terminal: ' + event.Test);
      assert.equal(event.Action, 'pass', event.Test + ' did not execute successfully');
      terminals.add(event.Test);
    }
  }
  assert.equal(roots.size, 66, 'exact native root denominator changed');
  assert.deepEqual([...roots].sort(), discovered, 'execution roots differ from fresh discovery');
  assert.deepEqual([...roots].sort(), [...rootTerminals].sort(), 'incomplete root terminals');
  assert.deepEqual([...children].sort(), [...childTerminals].sort(), 'incomplete child terminals');
  assert.ok(packageTerminal, 'missing native package terminal');
  for (const name of mandatory) {
    assert.ok(roots.has(name) && rootTerminals.has(name), 'missing mandatory root: ' + name);
  }
  const sourceStack = 'TestCrossLinuxRuntimeMatrixX86RawSourceStackNumerical';
  const continuation = 'TestCrossLinuxRuntimeMatrixX86ContinuationWholeCFGOriginalGoAndLLVM';
  const requiredChildren = [sourceStack + '/amd64', sourceStack + '/386'];
  for (const arch of ['amd64', '386']) {
    for (const dispatch of ['memory', 'register']) {
      requiredChildren.push(continuation + '/' + arch + '/' + dispatch);
    }
  }
  const packedStringFault = 'TestCrossLinuxRuntimeMatrixX86PackedStringOriginalNativeMemoryFaults';
  for (const optimization of ['-O0', '-O2']) {
    requiredChildren.push(packedStringFault + '/' + optimization);
  }
  const byteSwap = 'TestCrossLinuxRuntimeMatrixX86ByteSwapOriginalGoAndLLVM';
  for (const arch of ['amd64', '386']) {
    requiredChildren.push(byteSwap + '/' + arch);
  }
  const directTail386 = 'TestCrossLinuxRuntimeMatrixX86DirectTail386OriginalGoAndLLVM';
  for (const carrier of ['SI', 'BP', 'SI-stack', 'BP-stack']) {
    requiredChildren.push(directTail386 + '/' + carrier);
  }
  for (const dispatch of ['BP-memory', 'BP-register', 'BP-target']) {
    requiredChildren.push(continuation + '/386/' + dispatch);
  }
  const bitTest = 'TestCrossLinuxRuntimeMatrixX86BitTestNumericalAndAliases';
  for (const api of ['text', 'module', 'Go']) {
    for (const axis of ['backend_O0', 'IR_O2/backend_O2']) {
      requiredChildren.push(`${bitTest}/${api}/${axis}`);
    }
  }
  for (const child of requiredChildren) {
    assert.ok(children.has(child) && childTerminals.has(child), 'missing required child: ' + child);
  }
  return {
    protocol: 'go_test_json_native66',
    roots: roots.size, passed: rootTerminals.size,
    children: children.size, childPassed: childTerminals.size,
    failed: 0, skipped: 0, incomplete: 0, duplicate: 0,
    inventories: actualFiles.length, mandatory: [...mandatory].sort(), requiredChildren,
    packageResult: packageTerminal,
  };
}


module.exports = { auditNativePriority };

if (require.main === module) {
  assert.equal(process.argv.length, 3, 'one native artifact directory required');
  process.stdout.write(JSON.stringify(auditNativePriority(process.argv[2]), null, 2) + '\n');
}
