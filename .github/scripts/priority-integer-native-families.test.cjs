'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {auditIntegerNativeFamilies} = require('./audit-integer-native-families.cjs');

// Independent owner/axis inventory: do not import the auditor's denominator.
const owners = [
  'TestCrossLinuxRuntimeMatrixX86MOVNTIOriginalFlagsAndFaults',
  'TestCrossLinuxRuntimeMatrixX86PackedAlignLegacyNativeFaults',
  'TestCrossLinuxRuntimeMatrixX86ImplicitDivideOriginalGoAndNativeAMD64',
  'TestCrossLinuxRuntimeMatrixX86ImplicitDivideOriginalGoAndNative386',
  'TestCrossLinuxRuntimeMatrixX86SegmentQueryOriginalFlagsAliasesAndFaults',
  'TestCrossLinuxRuntimeMatrixX86MoveHalfOriginalGoFlagsDFAliases',
  'TestCrossLinuxRuntimeMatrixX86ImplicitDivideLogicalFPOriginalGoAndNativeAMD64',
  'TestCrossLinuxRuntimeMatrixX86ImplicitDivideLogicalFPOriginalGoAndNative386',
];
const axes = ['backend_O0', 'backend_O2', 'IR_O2/backend_O2'];
const packageName = 'github.com/xgo-dev/plan9asm';
const hash = 'a'.repeat(64);
const imageHash = 'b'.repeat(64);
const inventory = owners.join('\n') + '\nok\t' + packageName + '\n';
const host = `IA32 direct host: linux/amd64 kernel=x86_64 CPUsha=${hash} mapsha=${hash}\n`;
const staticImage = `native oracle static IA32 ELF bytes=4096 sha256=${imageHash}\n`;
const directImage = args => `IA32 direct ELF bytes=4096 sha256=${imageHash} argv=${args}\n`;
const sdk = args => `actual executable=/sdk/bin/go sha256=${hash} argv=${args}\n`;
const originalArgs = '["-test.run=^TestOriginal$" "-test.count=1" "-test.v"]';
const compileArgs = '["test" "-p=1" "-vet=off" "-c" "-o" "/tmp/owned/original.test" "."]';
const segmentEvidence = '48 original-Go opcode rows × 16 inputs; full GP aliases, six status flags, canaries; 160 live/dead m16 fault processes\n';
const halfPreflight = 'half native CPUID/XCR0 AVX512F=1; original EVEX transport opcode executed\n';
const halfEvidence = 'half native full64/FLAGS/DF=1/canary outcomes=512; complete original STD/CLD source and all eight named half moves\n';
const halfOriginal = 'half actual original Go full64/FLAGS/DF=1/canary outcomes=512\n';
function logicalFPEvidence(owner, original = false) {
  const arch = owner.endsWith('386') ? '386' : 'amd64';
  const rows = arch === '386' ? 6 : 8;
  const values = arch === '386' ? 96 : 128;
  const faults = arch === '386' ? 18 : 24;
  return original
    ? `logical FP actual original Go arch=${arch} rows=${rows} values=${values}; complete original FP divisor source and whole AX/DX/DF/canary observations\n`
    : `logical FP native arch=${arch} rows=${rows} values=${values} dead-division-faults=${faults}; whole AX/DX, DF and canaries; zero/overflow and signed-min/-1 SIGFPE\n`;
}
const event = (Action, Test, Output) => ({Action, Package: packageName,
  ...(Test ? {Test} : {}), ...(Output !== undefined ? {Output} : {})});
const serialize = events => events.map(value => JSON.stringify(value)).join('\n');

function completeEvents() {
  const events = [event('start')];
  for (const owner of owners) {
    const observed = owner.includes('ImplicitDivide') || owner.includes('SegmentQuery') || owner.includes('MoveHalf');
    const ia32 = owner.endsWith('386');
    events.push(event('run', owner));
    if (observed) events.push(event('output', owner, host));
    if (owner.includes('MoveHalf')) events.push(event('output', owner, halfPreflight));
    for (const axis of axes) {
      const child = owner + '/' + axis;
      events.push(event('run', child));
      if (ia32) {
        events.push(event('output', child, staticImage + directImage('[]') + staticImage));
      }
      if (owner.includes('SegmentQuery')) events.push(event('output', child, segmentEvidence));
      if (owner.includes('MoveHalf')) events.push(event('output', child, halfEvidence));
      if (owner.includes('LogicalFP')) events.push(event('output', child, logicalFPEvidence(owner)));
      events.push(event('pass', child));
    }
    if (observed) {
      events.push(event('output', owner, sdk('["version"]') + sdk(compileArgs)));
      if (ia32) events.push(event('output', owner, staticImage + directImage(originalArgs)));
      if (owner.includes('MoveHalf')) events.push(event('output', owner, halfOriginal));
      if (owner.includes('LogicalFP')) events.push(event('output', owner, logicalFPEvidence(owner, true)));
      events.push(event('output', owner, host));
    }
    events.push(event('pass', owner));
  }
  events.push(event('pass'));
  return events;
}

test('native integer families require all eight roots and twenty-four complete execution axes', () => {
  assert.deepEqual(auditIntegerNativeFamilies(inventory, serialize(completeEvents())),
    {roots: 8, children: 24, passed: 32, skipped: 0, incomplete: 0,
      nativeHosts: 12, sdkBuilds: 6, staticIA32Images: 14, directIA32Executions: 8});
});

test('logical FP division requires every actual native and original Go completion', () => {
  for (const owner of owners.filter(name => name.includes('LogicalFP'))) {
    for (const name of [owner, ...axes.map(axis => owner + '/' + axis)]) {
      const marker = logicalFPEvidence(owner, name === owner);
      for (const replacement of ['', marker + marker, marker.replace('rows=', 'partial-rows='),
        marker.replace('arch=', 'emulated-arch='), marker.replace('values=', 'ignored-values=')]) {
        const changed = completeEvents().map(value => value.Test === name && value.Output
          ? {...value, Output: value.Output.replace(marker, replacement)} : value);
        assert.throws(() => auditIntegerNativeFamilies(inventory, serialize(changed)), name);
      }
      const early = completeEvents();
      const at = early.findIndex(value => value.Test === name && value.Output?.includes(marker));
      const [completion] = early.splice(at, 1);
      const beforeRun = early.findIndex(value => value.Test === name && value.Action === 'run');
      early.splice(beforeRun, 0, completion);
      assert.throws(() => auditIntegerNativeFamilies(inventory, serialize(early)), 'completion before run');
      const late = completeEvents();
      const terminal = late.findIndex(value => value.Test === name && value.Action === 'pass');
      late.splice(terminal + 1, 0, event('output', name, marker));
      assert.throws(() => auditIntegerNativeFamilies(inventory, serialize(late)), 'completion after terminal');
    }
  }
});

test('native integer families reject each missing, failed, skipped or duplicate terminal', () => {
  const names = owners.flatMap(owner => [owner, ...axes.map(axis => owner + '/' + axis)]);
  for (const name of names) {
    const original = completeEvents();
    for (const Action of ['fail', 'skip']) {
      assert.throws(() => auditIntegerNativeFamilies(inventory,
        serialize(original.map(value => value.Action === 'pass' && value.Test === name
          ? {...value, Action} : value))), name + '/' + Action);
    }
    for (const Action of ['run', 'pass']) {
      const at = original.findIndex(value => value.Action === Action && value.Test === name);
      assert.throws(() => auditIntegerNativeFamilies(inventory,
        serialize(original.filter((_, index) => index !== at))), name + '/missing ' + Action);
      const duplicate = original.slice();
      duplicate.splice(at, 0, original[at]);
      assert.throws(() => auditIntegerNativeFamilies(inventory, serialize(duplicate)),
        name + '/duplicate ' + Action);
    }
  }
});

test('native integer families reject malformed packages, inventory changes and printed success', () => {
  for (const changed of ['', inventory + owners[0] + '\n', inventory.replace(owners[0] + '\n', '')]) {
    assert.throws(() => auditIntegerNativeFamilies(changed, serialize(completeEvents())));
  }
  for (const changed of [
    [event('output', undefined, '16 passed')],
    completeEvents().slice(1),
    completeEvents().slice(0, -1),
    [event('start'), ...completeEvents()],
    [...completeEvents(), event('pass')],
    [...completeEvents(), {Action: 'build-output', ImportPath: 'runtime', Output: 'late'}],
    [event('run', owners[0] + '/objects-only'), ...completeEvents()],
    completeEvents().map(value => ({...value, Package: 'foreign/package'})),
  ]) assert.throws(() => auditIntegerNativeFamilies(inventory, serialize(changed)));
  for (const value of [event('unknown'), event('output', owners[0], 'late output')]) {
    const changed = completeEvents();
    changed.splice(-1, 0, value);
    assert.throws(() => auditIntegerNativeFamilies(inventory, serialize(changed)));
  }
  assert.throws(() => auditIntegerNativeFamilies(inventory, '{not JSON}'));
});

test('division and segment native hosts and actual Go SDK builds bracket all three axes', () => {
  for (const owner of owners.slice(2)) {
    for (const replacement of ['', host.replace('linux/amd64', 'linux/arm64'),
      host.replace('kernel=x86_64', 'kernel=aarch64'), host.replace(hash, 'not-a-digest')]) {
      const changed = completeEvents().map(value => value.Test === owner && value.Output === host
        ? {...value, Output: replacement} : value);
      assert.throws(() => auditIntegerNativeFamilies(inventory, serialize(changed)), owner);
    }
    for (const needle of ['["version"]', compileArgs]) {
      const changed = completeEvents().map(value => value.Test === owner && value.Output
        ? {...value, Output: value.Output.replace(sdk(needle), '')} : value);
      assert.throws(() => auditIntegerNativeFamilies(inventory, serialize(changed)), needle);
    }
    const changed = completeEvents();
    const before = changed.findIndex(value => value.Test === owner && value.Output === host);
    const [late] = changed.splice(before, 1);
    changed.splice(before + 2, 0, late);
    assert.throws(() => auditIntegerNativeFamilies(inventory, serialize(changed)), 'late preflight');
    const wrongTool = completeEvents().map(value => value.Test === owner && value.Output
      ? {...value, Output: value.Output.replaceAll('/sdk/bin/go', '/other/bin/go')} : value);
    // A different actual SDK path is valid if both commands bind the same tool.
    assert.doesNotThrow(() => auditIntegerNativeFamilies(inventory, serialize(wrongTool)));
    const splitTool = completeEvents().map(value => value.Test === owner && value.Output
      ? {...value, Output: value.Output.replace(sdk(compileArgs), sdk(compileArgs).replace(hash, imageHash))}
      : value);
    assert.throws(() => auditIntegerNativeFamilies(inventory, serialize(splitTool)), 'changed SDK');
    const liveHostHashes = completeEvents();
    const lastHost = liveHostHashes.findLastIndex(value => value.Test === owner && value.Output === host);
    liveHostHashes[lastHost] = {...liveHostHashes[lastHost], Output: host.replaceAll(hash, imageHash)};
    assert.doesNotThrow(() => auditIntegerNativeFamilies(inventory, serialize(liveHostHashes)));
    const unboundArgs = completeEvents().map(value => value.Test === owner && value.Output
      ? {...value, Output: value.Output.replace('"-p=1" "-vet=off"', '"-p=8"')} : value);
    assert.throws(() => auditIntegerNativeFamilies(inventory, serialize(unboundArgs)), 'changed build');
    const missingPost = completeEvents();
    const post = missingPost.findLastIndex(value => value.Test === owner && value.Output === host);
    missingPost.splice(post, 1);
    assert.throws(() => auditIntegerNativeFamilies(inventory, serialize(missingPost)), 'missing final host');
    const earlyGo = completeEvents();
    const goAt = earlyGo.findIndex(value => value.Test === owner && value.Output?.includes('actual executable='));
    const [originalGo] = earlyGo.splice(goAt, 1);
    const finalChild = earlyGo.findIndex(value => value.Test === owner + '/' + axes[2] && value.Action === 'pass');
    earlyGo.splice(finalChild, 0, originalGo);
    assert.throws(() => auditIntegerNativeFamilies(inventory, serialize(earlyGo)), 'Go before final axis');
  }
});

test('segment query axes require their complete actual opcode flags alias and fault evidence', () => {
  const owner = owners[4];
  for (const axis of axes) {
    for (const replacement of ['', segmentEvidence.replace('160', '159'),
      segmentEvidence.replace('six status flags', 'ZF only')]) {
      const changed = completeEvents().map(value => value.Test === owner + '/' + axis && value.Output
        ? {...value, Output: value.Output.replace(segmentEvidence, replacement)} : value);
      assert.throws(() => auditIntegerNativeFamilies(inventory, serialize(changed)), axis);
    }
  }
});

test('native half moves require actual CPU original Go and each complete DF=1 axis', () => {
  const owner = owners[5];
  for (const name of [owner, ...axes.map(axis => owner + '/' + axis)]) {
    const needles = name === owner ? [halfPreflight, halfOriginal] : [halfEvidence];
    for (const needle of needles) {
      for (const replacement of ['', needle + needle, needle.replace('=512', '=511').replace('AVX512F=1', 'AVX512F=0')]) {
        if (replacement === needle) continue;
        const changed = completeEvents().map(value => value.Test === name && value.Output
          ? {...value, Output: value.Output.replace(needle, replacement)} : value);
        assert.throws(() => auditIntegerNativeFamilies(inventory, serialize(changed)), name);
      }
    }
  }
});

test('division IA32 requires actual static and direct images in every axis and original Go', () => {
  for (const owner of [owners[3], owners[7]]) {
    const required = [owner, ...axes.map(axis => owner + '/' + axis)];
    for (const name of required) {
      for (const needle of [staticImage, directImage(name === owner ? originalArgs : '[]')]) {
        const changed = completeEvents().map(value => value.Test === name && value.Output
          ? {...value, Output: value.Output.replace(needle, '')} : value);
        assert.throws(() => auditIntegerNativeFamilies(inventory, serialize(changed)), name + needle);
      }
    }
  }
  for (const replacement of ['bytes=0', 'bytes=-1', 'bytes=guest']) {
    const changed = completeEvents().map(value => value.Output
      ? {...value, Output: value.Output.replaceAll('bytes=4096', replacement)} : value);
    assert.throws(() => auditIntegerNativeFamilies(inventory, serialize(changed)), replacement);
  }
  const forged = completeEvents().map(value => value.Output
    ? {...value, Output: value.Output.replaceAll('IA32 direct ELF', 'QEMU translated ELF')} : value);
  assert.throws(() => auditIntegerNativeFamilies(inventory, serialize(forged)));
});
