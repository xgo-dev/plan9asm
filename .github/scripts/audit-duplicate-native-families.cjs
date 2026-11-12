'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {auditNativeOwners} = require('./audit-native-owners.cjs');
const {requireIA32Images, requireSDKCommands} = require('./audit-integer-native-families.cjs');

const roots = [
  'TestCrossLinuxRuntimeMatrixX86DuplicateMoveOriginalGoAndNativeAMD64',
  'TestCrossLinuxRuntimeMatrixX86DuplicateMoveOriginalGoAndNative386',
];
const nativeAxes = ['backend_O0', 'backend_O2', 'IR_O2/backend_O2'];
const axes = [...nativeAxes, 'OriginalGo'];
const children = roots.flatMap(root => axes.map(axis => root + '/' + axis));
const nativeHost = /IA32 direct host: linux\/amd64 kernel=x86_64 CPUsha=[a-f0-9]{64} mapsha=[a-f0-9]{64}\b/g;
const avxPreflight = /actual guest CPUID\/XCR0 preflight: AVX=1 AVX2=[01] AVX512F=[01]\r?\n/g;
const originalArgs = '["-test.run=^TestOriginal$" "-test.count=1" "-test.v"]';
const originalEvidence = 'actual original Go legacy/VEX: 18 rows × 16 IEEE/bit patterns × 6 masks = 1728 whole32/FLAGS/DF/MXCSR/canary outcomes; no EVEX execution claim\n';

function pipelineEvidence(arch) {
  return `duplicate native arch=${arch} live=60 dead=30 whole64-outcomes=5760 fault-processes=712; legacy original opcode/all mod16, E4NF/E5NF independent full-span references\n`;
}

function requireExecutableRoles(output, arch, original, commands, observed) {
  const receipts = [...output.matchAll(/actual executable=(\/[^\r\n]+?) sha256=([a-f0-9]{64}) argv=(\[[^\r\n]*\])\r?\n/g)];
  assert.equal(receipts.length, output.split('actual executable=').length - 1,
    'malformed actual executable receipt');
  assert.equal(receipts.length, (original ? 2 : 0) + (arch === '386' ? 1 : 0),
    'actual executable receipts escaped their original Go or native pipeline role');
  if (original) {
    assert.deepEqual(receipts.slice(0, 2).map(receipt => receipt.slice(1)),
      commands.map(command => command.slice(1)), 'SDK commands lost their explicit OriginalGo ownership');
  }
  if (arch !== '386') return;

  const executable = receipts[original ? 2 : 0];
  if (original) {
    const binary = / "-o" "([^"\r\n]+)" /.exec(commands[1][3]);
    assert.ok(binary, 'original Go build lost its exact output executable');
    assert.equal(executable[1], binary[1], 'original execution differs from the actual Go build output');
  } else {
    assert.equal(path.posix.basename(executable[1]), 'comparison',
      'native pipeline cannot substitute original Go compilation or a foreign executable');
  }
  assert.equal(executable[2], observed.images[0][2], 'actual executable differs from inspected IA32 image');
  assert.equal(executable[3], original ? originalArgs : '[]', 'actual executable arguments changed');
  assert.ok(observed.images[0].index < executable.index && executable.index < observed.direct[0].index,
    'actual executable escaped its inspected image/direct execution bracket');
}

// Each first-party wrapper supplies its own fixed inventory and exact program
// completion witnesses. Reports can never choose the denominator or family.
function auditSSEAVXNativeFamilies(inventory, raw, roots, pipelineEvidence, originalEvidence) {
  const children = roots.flatMap(root => axes.map(axis => root + '/' + axis));
  const result = auditNativeOwners(inventory, raw, roots, children);
  const outputs = new Map([...roots, ...children].map(name => [name, '']));
  const outputSpans = new Map(roots.map(root => [root, []]));
  const states = new Map();
  const childPasses = new Map();
  let packageStarted = false, packageComplete = false;
  let nativeHosts = 0, avxPreflights = 0, sdkBuilds = 0;
  let staticIA32Images = 0, directIA32Executions = 0;

  const events = raw.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
  for (const [sequence, event] of events.entries()) {
    assert.ok(!packageComplete, 'event after the complete duplicate package');
    if (event.Action === 'build-output' && event.ImportPath && !event.Test) continue;
    if (!event.Test) {
      assert.ok(['start', 'output', 'pass'].includes(event.Action), 'unknown duplicate package action');
      if (event.Action === 'start') {
        assert.ok(!packageStarted, 'duplicate native package start');
        packageStarted = true;
      } else {
        assert.ok(packageStarted, 'duplicate observation before package start');
        if (event.Action === 'output') assert.equal(typeof event.Output, 'string', 'package output must be text');
        if (event.Action === 'pass') packageComplete = true;
      }
      continue;
    }
    assert.ok(packageStarted, 'duplicate test before package start');
    assert.ok(['run', 'output', 'pass'].includes(event.Action), 'unknown duplicate test action');
    const root = event.Test.split('/')[0];
    const arch = root.endsWith('386') ? '386' : 'amd64';
    const original = event.Test === root + '/OriginalGo';
    if (event.Action === 'run') {
      states.set(event.Test, 'running');
      if (event.Test !== root) {
        const output = outputs.get(root);
        const hosts = [...output.matchAll(nativeHost)], preflights = [...output.matchAll(avxPreflight)];
        assert.equal(hosts.length, 1, 'duplicate axis lacks its preceding actual native host observation');
        assert.equal(preflights.length, 1, 'duplicate axis lacks actual AVX CPUID/XCR0 permission');
        assert.ok(hosts[0].index < preflights[0].index, 'duplicate AVX preflight preceded native host identity');
        assert.ok(!output.includes('actual executable='), 'original Go receipts must belong to its explicit child');
        if (original) {
          for (const axis of nativeAxes) {
            assert.equal(states.get(root + '/' + axis), 'passed', 'original Go preceded a complete native axis');
          }
        }
      }
      continue;
    }
    assert.equal(states.get(event.Test), 'running', 'duplicate observation after its terminal');
    if (event.Action === 'output') {
      assert.equal(typeof event.Output, 'string', 'duplicate output must be text');
      if (event.Test === root) outputSpans.get(root).push({offset: outputs.get(root).length, sequence});
      outputs.set(event.Test, outputs.get(event.Test) + event.Output);
      continue;
    }
    states.set(event.Test, 'passed');
    const output = outputs.get(event.Test);
    if (event.Test !== root) {
      childPasses.set(event.Test, sequence);
      assert.equal([...output.matchAll(nativeHost)].length, 0, 'child host cannot replace root native ownership');
      assert.equal([...output.matchAll(avxPreflight)].length, 0, 'child preflight cannot replace root AVX permission');
      const evidence = original ? originalEvidence : pipelineEvidence(arch);
      assert.equal(output.split(evidence).length - 1, 1, 'missing exact complete duplicate execution evidence');
      if (original) {
        const commands = requireSDKCommands(output);
        assert.ok(commands[1].index < output.indexOf(evidence), 'original Go terminal preceded actual SDK build');
        sdkBuilds++;
        let observed;
        if (arch === '386') {
          observed = requireIA32Images(output, 1, originalArgs);
          assert.ok(commands[1].index < observed.images[0].index &&
            observed.direct[0].index < output.indexOf(evidence), 'original Go IA32 execution escaped SDK/terminal bracket');
          staticIA32Images++;
          directIA32Executions++;
        }
        requireExecutableRoles(output, arch, true, commands, observed);
      } else {
        let observed;
        if (arch === '386') {
          observed = requireIA32Images(output, 2, '[]');
          assert.ok(observed.images[1].index < output.indexOf(evidence), 'fault image observation followed complete execution');
          staticIA32Images += 2;
          directIA32Executions++;
        }
        requireExecutableRoles(output, arch, false, undefined, observed);
      }
      continue;
    }

    const hosts = [...output.matchAll(nativeHost)], preflights = [...output.matchAll(avxPreflight)];
    assert.equal(hosts.length, 2, 'duplicate root must retain pre/post actual native host observations');
    assert.equal(preflights.length, 1, 'duplicate root must retain its single actual AVX preflight');
    assert.ok(!output.includes('actual executable='), 'SDK receipts escaped their OriginalGo child');
    for (const axis of axes) assert.equal(states.get(root + '/' + axis), 'passed', 'root preceded required child completion');
    const spans = outputSpans.get(root).filter(span => span.offset <= hosts[1].index);
    assert.ok(spans[spans.length - 1].sequence > childPasses.get(root + '/OriginalGo'),
      'final native host observation preceded complete original Go execution');
    // These are live host receipts, not immutable CPU MHz or map snapshots.
    nativeHosts += 2;
    avxPreflights++;
  }
  return {...result, nativeHosts, avxPreflights, sdkBuilds, staticIA32Images, directIA32Executions};
}

function auditDuplicateNativeFamilies(inventory, raw) {
  return auditSSEAVXNativeFamilies(inventory, raw, roots, pipelineEvidence, originalEvidence);
}

module.exports = {auditDuplicateNativeFamilies, auditSSEAVXNativeFamilies, roots, children};
if (require.main === module) {
  const directory = process.argv[2];
  const result = auditDuplicateNativeFamilies(fs.readFileSync(path.join(directory, 'inventory.log'), 'utf8'),
    fs.readFileSync(path.join(directory, 'raw.jsonl'), 'utf8'));
  process.stdout.write(JSON.stringify(result) + '\n');
}
