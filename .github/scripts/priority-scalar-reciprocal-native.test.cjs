'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');

// Deliberately independent of the implementation's denominator and receipts.
const roots = [
  'TestCrossLinuxRuntimeMatrixX86ScalarReciprocalOriginalGoAndNativeAMD64',
  'TestCrossLinuxRuntimeMatrixX86ScalarReciprocalOriginalGoAndNative386',
];
const axes = ['backend_O0', 'backend_O2', 'IR_O2/backend_O2', 'OriginalGo'];
const hash = 'a'.repeat(64), imageHash = 'b'.repeat(64);
const host = `IA32 direct host: linux/amd64 kernel=x86_64 CPUsha=${hash} mapsha=${hash}\n`;
const avx = 'actual guest CPUID/XCR0 preflight: AVX=1 AVX2=0 AVX512F=0\n';
const image = `native oracle static IA32 ELF bytes=4096 sha256=${imageHash}\n`;
const direct = args => `IA32 direct ELF bytes=4096 sha256=${imageHash} argv=${args}\n`;
const sdk = args => `actual executable=/sdk/bin/go sha256=${hash} argv=${args}\n`;
const executable = (filename, args) => `actual executable=/tmp/owned/${filename} sha256=${imageHash} argv=${args}\n`;
const originalArgs = '["-test.run=^TestOriginal$" "-test.count=1" "-test.v"]';
const compileArgs = '["test" "-p=1" "-vet=off" "-c" "-o" "/tmp/owned/original.test" "."]';
const evidence = arch => `scalar estimates native arch=${arch} live=20 dead=4 whole32-outcomes=30720 fault-processes=40; SSE/AVX actual scalar opcodes, no AVX512/Z transport\n`;
const originalEvidence = 'actual original Go scalar estimates: 20 aliases × 24 bit patterns × 64 MXCSR profiles = 30720 whole32/FLAGS/DF/MXCSR/canary outcomes; independent scalar references, no AVX512/Z execution claim\n';
const inventory = roots.join('\n') + '\nok\tgithub.com/xgo-dev/plan9asm\n';
const event = (Action, Test, Output) => ({Action, Package: 'github.com/xgo-dev/plan9asm',
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
          image + executable('original.test', originalArgs) + direct(originalArgs)));
        events.push(event('output', child, originalEvidence));
      } else {
        if (arch === '386') events.push(event('output', child,
          image + executable('comparison', '[]') + direct('[]') + image));
        events.push(event('output', child, evidence(arch)));
      }
      events.push(event('pass', child));
    }
    events.push(event('output', root, host), event('pass', root));
  }
  events.push(event('pass'));
  return events;
}

function audit(events = completeEvents(), discovered = inventory) {
  const auditor = '.github/scripts/audit-scalar-reciprocal-native.cjs';
  assert.ok(fs.existsSync(auditor), 'scalar estimates lack an independent strict native completion auditor');
  return require('./audit-scalar-reciprocal-native.cjs').auditScalarReciprocalNative(discovered, serialize(events));
}

test('scalar estimate native ownership requires two roots, three optimized native axes and actual Go', () => {
  assert.deepEqual(audit(), {roots: 2, children: 8, passed: 10, skipped: 0, incomplete: 0,
    nativeHosts: 4, avxPreflights: 2, sdkBuilds: 2, staticIA32Images: 7, directIA32Executions: 4});
});

test('scalar estimates reject every missing duplicate skipped failed or incomplete execution terminal', () => {
  audit(); // A failing/missing auditor must not make the negative controls pass.
  for (const name of roots.flatMap(root => [root, ...axes.map(axis => root + '/' + axis)])) {
    for (const Action of ['fail', 'skip']) {
      assert.throws(() => audit(completeEvents().map(value => value.Action === 'pass' && value.Test === name
        ? {...value, Action} : value)), name + Action);
    }
    for (const Action of ['run', 'pass']) {
      const events = completeEvents();
      const at = events.findIndex(value => value.Test === name && value.Action === Action);
      assert.throws(() => audit(events.filter((_, index) => index !== at)), name + ' missing ' + Action);
      events.splice(at, 0, events[at]);
      assert.throws(() => audit(events), name + ' duplicate ' + Action);
    }
  }
  for (const changed of ['', inventory + roots[0] + '\n', inventory.replace(roots[0] + '\n', '')]) {
    assert.throws(() => audit(completeEvents(), changed));
  }
  for (const events of [completeEvents().slice(1), completeEvents().slice(0, -1),
    [...completeEvents(), event('pass')], [event('start'), ...completeEvents()],
    completeEvents().map(value => ({...value, Package: 'foreign/package'}))]) assert.throws(() => audit(events));
});

test('scalar estimates require real host brackets AVX OS permission SDK identities and direct static IA32', () => {
  audit();
  for (const root of roots) {
    const arch = root.endsWith('386') ? '386' : 'amd64';
    for (const needle of [host, avx]) {
      for (const replacement of ['', needle + needle, needle.replace('linux/amd64', 'linux/arm64'),
        needle.replace('AVX=1', 'AVX=0'), needle.replace(hash, 'invalid')]) {
        if (replacement === needle) continue;
        assert.throws(() => audit(completeEvents().map(value => value.Test === root && value.Output
          ? {...value, Output: value.Output.replace(needle, replacement)} : value)));
      }
    }
    for (const axis of axes) {
      const child = root + '/' + axis;
      const receipt = axis === 'OriginalGo' ? originalEvidence : evidence(arch);
      for (const replacement of ['', receipt + receipt, receipt.replaceAll('30720', '30719')]) {
        assert.throws(() => audit(completeEvents().map(value => value.Test === child && value.Output
          ? {...value, Output: value.Output.replace(receipt, replacement)} : value)));
      }
      const required = [];
      if (axis === 'OriginalGo') required.push(sdk('["version"]'), sdk(compileArgs));
      if (arch === '386') required.push(image, direct(axis === 'OriginalGo' ? originalArgs : '[]'));
      for (const needle of required) {
        assert.throws(() => audit(completeEvents().map(value => value.Test === child && value.Output
          ? {...value, Output: value.Output.replace(needle, '')} : value)));
      }
    }
  }
  const child = roots[1] + '/OriginalGo';
  for (const needle of [sdk(compileArgs), direct(originalArgs)]) {
    assert.throws(() => audit(completeEvents().map(value => value.Test === child && value.Output
      ? {...value, Output: value.Output.replace(needle, needle.replace(needle.includes('actual executable') ? hash : imageHash, 'c'.repeat(64)))} : value)));
  }
  const events = completeEvents();
  const original = events.filter(value => value.Test === roots[0] + '/OriginalGo');
  const earlier = events.filter(value => value.Test !== roots[0] + '/OriginalGo');
  const at = earlier.findIndex(value => value.Test === roots[0] + '/' + axes[2] && value.Action === 'pass');
  earlier.splice(at, 0, ...original);
  assert.throws(() => audit(earlier), 'actual Go cannot precede a finished native axis');
});

test('scalar estimate executable receipts cannot replace or escape original Go ownership', () => {
  audit();
  for (const axis of axes) {
    const child = roots[1] + '/' + axis;
    const original = axis === 'OriginalGo';
    const receipt = executable(original ? 'original.test' : 'comparison', original ? originalArgs : '[]');
    for (const replacement of ['', receipt + receipt,
      receipt.replace(imageHash, hash), receipt.replace('sha256=' + imageHash, 'sha256=invalid'),
      receipt.replace(original ? 'original.test' : 'comparison', 'unrelated'),
      receipt.replace(original ? originalArgs : '[]', '["unobserved"]'), sdk(compileArgs)]) {
      assert.throws(() => audit(completeEvents().map(value => value.Test === child && value.Output
        ? {...value, Output: value.Output.replace(receipt, replacement)} : value)), axis + '/foreign or absent executable');
    }
    const events = completeEvents();
    const at = events.findIndex(value => value.Test === child && value.Output?.includes(receipt));
    events[at].Output = events[at].Output.replace(receipt, '');
    const first = events.findIndex(value => value.Test === child && value.Action === 'output');
    events.splice(first, 0, event('output', child, receipt));
    assert.throws(() => audit(events), axis + '/execution before inspected image');
  }
  const events = completeEvents();
  const child = roots[1] + '/OriginalGo';
  const at = events.findIndex(value => value.Test === child && value.Output?.includes(sdk(compileArgs)));
  events[at].Output = events[at].Output.replace(sdk(compileArgs), '');
  const pipeline = events.findIndex(value => value.Test === roots[1] + '/backend_O0' && value.Action === 'output');
  events.splice(pipeline, 0, event('output', roots[1] + '/backend_O0', sdk(compileArgs)));
  assert.throws(() => audit(events), 'pipeline cannot own original Go compilation');
});
