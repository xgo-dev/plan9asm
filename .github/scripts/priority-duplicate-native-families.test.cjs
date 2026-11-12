'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {auditDuplicateNativeFamilies} = require('./audit-duplicate-native-families.cjs');

// This denominator is independent of the production auditor's inventory.
const roots = [
  'TestCrossLinuxRuntimeMatrixX86DuplicateMoveOriginalGoAndNativeAMD64',
  'TestCrossLinuxRuntimeMatrixX86DuplicateMoveOriginalGoAndNative386',
];
const axes = ['backend_O0', 'backend_O2', 'IR_O2/backend_O2', 'OriginalGo'];
const packageName = 'github.com/xgo-dev/plan9asm';
const inventory = roots.join('\n') + '\nok\t' + packageName + '\n';
const hash = 'a'.repeat(64), imageHash = 'b'.repeat(64);
const host = `IA32 direct host: linux/amd64 kernel=x86_64 CPUsha=${hash} mapsha=${hash}\n`;
const avx = 'actual guest CPUID/XCR0 preflight: AVX=1 AVX2=0 AVX512F=0\n';
const staticImage = `native oracle static IA32 ELF bytes=4096 sha256=${imageHash}\n`;
const directImage = args => `IA32 direct ELF bytes=4096 sha256=${imageHash} argv=${args}\n`;
const sdk = args => `actual executable=/sdk/bin/go sha256=${hash} argv=${args}\n`;
const executable = (filename, args) => `actual executable=/tmp/owned/${filename} sha256=${imageHash} argv=${args}\n`;
const originalArgs = '["-test.run=^TestOriginal$" "-test.count=1" "-test.v"]';
const compileArgs = '["test" "-p=1" "-vet=off" "-c" "-o" "/tmp/owned/original.test" "."]';
const pipelineEvidence = arch => `duplicate native arch=${arch} live=60 dead=30 whole64-outcomes=5760 fault-processes=712; legacy original opcode/all mod16, E4NF/E5NF independent full-span references\n`;
const originalEvidence = 'actual original Go legacy/VEX: 18 rows × 16 IEEE/bit patterns × 6 masks = 1728 whole32/FLAGS/DF/MXCSR/canary outcomes; no EVEX execution claim\n';
const event = (Action, Test, Output) => ({Action, Package: packageName,
  ...(Test ? {Test} : {}), ...(Output !== undefined ? {Output} : {})});
const serialize = events => events.map(value => JSON.stringify(value)).join('\n');

function completeEvents() {
  const events = [event('start')];
  for (const root of roots) {
    const arch = root.endsWith('386') ? '386' : 'amd64';
    events.push(event('run', root), event('output', root, host + avx));
    for (const axis of axes) {
      const child = root + '/' + axis;
      events.push(event('run', child));
      if (axis === 'OriginalGo') {
        events.push(event('output', child, sdk('["version"]') + sdk(compileArgs)));
        if (arch === '386') events.push(event('output', child,
          staticImage + executable('original.test', originalArgs) + directImage(originalArgs)));
        events.push(event('output', child, originalEvidence));
      } else {
        if (arch === '386') events.push(event('output', child,
          staticImage + executable('comparison', '[]') + directImage('[]') + staticImage));
        events.push(event('output', child, pipelineEvidence(arch)));
      }
      events.push(event('pass', child));
    }
    events.push(event('output', root, host), event('pass', root));
  }
  events.push(event('pass'));
  return events;
}

test('duplicate moves independently require two native roots and all four execution children', () => {
  assert.deepEqual(auditDuplicateNativeFamilies(inventory, serialize(completeEvents())),
    {roots: 2, children: 8, passed: 10, skipped: 0, incomplete: 0,
      nativeHosts: 4, avxPreflights: 2, sdkBuilds: 2, staticIA32Images: 7, directIA32Executions: 4});
});

test('duplicate moves reject every absent duplicated failed or skipped required terminal', () => {
  for (const name of roots.flatMap(root => [root, ...axes.map(axis => root + '/' + axis)])) {
    for (const Action of ['fail', 'skip']) {
      assert.throws(() => auditDuplicateNativeFamilies(inventory,
        serialize(completeEvents().map(value => value.Action === 'pass' && value.Test === name
          ? {...value, Action} : value))), name + Action);
    }
    for (const Action of ['run', 'pass']) {
      const events = completeEvents();
      const at = events.findIndex(value => value.Test === name && value.Action === Action);
      assert.throws(() => auditDuplicateNativeFamilies(inventory,
        serialize(events.filter((_, index) => index !== at))), name + '/missing ' + Action);
      events.splice(at, 0, events[at]);
      assert.throws(() => auditDuplicateNativeFamilies(inventory, serialize(events)), name + '/duplicate ' + Action);
    }
  }
});

test('duplicate moves reject stale inventory malformed lifecycle foreign children and printed PASS', () => {
  for (const changed of ['', inventory + roots[0] + '\n', inventory.replace(roots[0] + '\n', '')]) {
    assert.throws(() => auditDuplicateNativeFamilies(changed, serialize(completeEvents())));
  }
  for (const changed of [
    [event('output', undefined, '10 passed')], completeEvents().slice(1), completeEvents().slice(0, -1),
    [event('start'), ...completeEvents()], [...completeEvents(), event('pass')],
    [...completeEvents(), {Action: 'build-output', ImportPath: 'runtime', Output: 'late'}],
    [event('run', roots[0] + '/objects-only'), ...completeEvents()],
    completeEvents().map(value => ({...value, Package: 'foreign/package'})),
  ]) assert.throws(() => auditDuplicateNativeFamilies(inventory, serialize(changed)));
  for (const changed of [event('unknown'), event('output', roots[0], 'late')]) {
    const events = completeEvents();
    events.splice(-1, 0, changed);
    assert.throws(() => auditDuplicateNativeFamilies(inventory, serialize(events)));
  }
  assert.throws(() => auditDuplicateNativeFamilies(inventory, '{not JSON}'));
});

test('duplicate moves require native host brackets AVX and complete per-axis evidence', () => {
  for (const root of roots) {
    const arch = root.endsWith('386') ? '386' : 'amd64';
    for (const needle of [host, avx]) {
      for (const replacement of ['', needle.replace('linux/amd64', 'linux/arm64'),
        needle.replace('AVX=1', 'AVX=0'), needle.replace(hash, 'invalid')]) {
        if (replacement === needle) continue;
        const events = completeEvents().map(value => value.Test === root && value.Output
          ? {...value, Output: value.Output.replace(needle, replacement)} : value);
        assert.throws(() => auditDuplicateNativeFamilies(inventory, serialize(events)), needle);
      }
    }
    for (const axis of axes) {
      const evidence = axis === 'OriginalGo' ? originalEvidence : pipelineEvidence(arch);
      for (const replacement of ['', evidence.replace('1728', '1727').replace('712', '711'), evidence + evidence]) {
        const events = completeEvents().map(value => value.Test === root + '/' + axis && value.Output
          ? {...value, Output: value.Output.replace(evidence, replacement)} : value);
        assert.throws(() => auditDuplicateNativeFamilies(inventory, serialize(events)), axis);
      }
    }
    const events = completeEvents();
    const original = events.filter(value => value.Test === root + '/OriginalGo');
    const earlier = events.filter(value => value.Test !== root + '/OriginalGo');
    const at = earlier.findIndex(value => value.Test === root + '/' + axes[2] && value.Action === 'pass');
    earlier.splice(at, 0, ...original);
    assert.throws(() => auditDuplicateNativeFamilies(inventory, serialize(earlier)), 'Go before final native axis');
  }
});

test('duplicate original Go requires actual SDK and 386 direct image identity in the OriginalGo child', () => {
  for (const root of roots) {
    const child = root + '/OriginalGo';
    for (const needle of [sdk('["version"]'), sdk(compileArgs)]) {
      const events = completeEvents().map(value => value.Test === child && value.Output
        ? {...value, Output: value.Output.replace(needle, '')} : value);
      assert.throws(() => auditDuplicateNativeFamilies(inventory, serialize(events)), needle);
    }
    const events = completeEvents().map(value => value.Test === child && value.Output
      ? {...value, Output: value.Output.replace(sdk(compileArgs), sdk(compileArgs).replace(hash, imageHash))} : value);
    assert.throws(() => auditDuplicateNativeFamilies(inventory, serialize(events)), 'changed SDK identity');
  }
  for (const axis of axes) {
    const child = roots[1] + '/' + axis;
    const args = axis === 'OriginalGo' ? originalArgs : '[]';
    for (const needle of [staticImage, directImage(args)]) {
      const events = completeEvents().map(value => value.Test === child && value.Output
        ? {...value, Output: value.Output.replace(needle, '')} : value);
      assert.throws(() => auditDuplicateNativeFamilies(inventory, serialize(events)), child + needle);
    }
    for (const replacement of ['bytes=0', 'bytes=-1', 'bytes=guest']) {
      const events = completeEvents().map(value => value.Test === child && value.Output
        ? {...value, Output: value.Output.replaceAll('bytes=4096', replacement)} : value);
      assert.throws(() => auditDuplicateNativeFamilies(inventory, serialize(events)), replacement);
    }
    const changedImage = completeEvents().map(value => value.Test === child && value.Output
      ? {...value, Output: value.Output.replace(directImage(args), directImage(args).replace(imageHash, hash))} : value);
    assert.throws(() => auditDuplicateNativeFamilies(inventory, serialize(changedImage)), 'changed actual image');
  }
});

test('duplicate actual executable receipts retain precise pipeline and original Go roles', () => {
  auditDuplicateNativeFamilies(inventory, serialize(completeEvents()));
  for (const axis of axes) {
    const child = roots[1] + '/' + axis;
    const original = axis === 'OriginalGo';
    const receipt = executable(original ? 'original.test' : 'comparison', original ? originalArgs : '[]');
    for (const replacement of ['', receipt + receipt,
      receipt.replace(imageHash, hash), receipt.replace('sha256=' + imageHash, 'sha256=invalid'),
      receipt.replace(original ? 'original.test' : 'comparison', 'unrelated'),
      receipt.replace(original ? originalArgs : '[]', '["unobserved"]'), sdk(compileArgs)]) {
      const events = completeEvents().map(value => value.Test === child && value.Output
        ? {...value, Output: value.Output.replace(receipt, replacement)} : value);
      assert.throws(() => auditDuplicateNativeFamilies(inventory, serialize(events)), axis + '/foreign or absent executable');
    }
    const events = completeEvents();
    const at = events.findIndex(value => value.Test === child && value.Output?.includes(receipt));
    events[at].Output = events[at].Output.replace(receipt, '');
    const first = events.findIndex(value => value.Test === child && value.Action === 'output');
    events.splice(first, 0, event('output', child, receipt));
    assert.throws(() => auditDuplicateNativeFamilies(inventory, serialize(events)), axis + '/execution before inspected image');
  }
  const events = completeEvents();
  const child = roots[1] + '/OriginalGo';
  const at = events.findIndex(value => value.Test === child && value.Output?.includes(sdk(compileArgs)));
  events[at].Output = events[at].Output.replace(sdk(compileArgs), '');
  const pipeline = events.findIndex(value => value.Test === roots[1] + '/backend_O0' && value.Action === 'output');
  events.splice(pipeline, 0, event('output', roots[1] + '/backend_O0', sdk(compileArgs)));
  assert.throws(() => auditDuplicateNativeFamilies(inventory, serialize(events)), 'pipeline cannot own original Go compilation');
});
