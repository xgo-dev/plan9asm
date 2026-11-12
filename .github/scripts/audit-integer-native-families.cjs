'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {auditNativeOwners} = require('./audit-native-owners.cjs');

const roots = [
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
const children = roots.flatMap(root => axes.map(axis => root + '/' + axis));
const nativeHost = /IA32 direct host: linux\/amd64 kernel=x86_64 CPUsha=[a-f0-9]{64} mapsha=[a-f0-9]{64}\b/g;
const originalArgs = '["-test.run=^TestOriginal$" "-test.count=1" "-test.v"]';
const segmentEvidence = '48 original-Go opcode rows × 16 inputs; full GP aliases, six status flags, canaries; 160 live/dead m16 fault processes\n';
const halfPreflight = 'half native CPUID/XCR0 AVX512F=1; original EVEX transport opcode executed\n';
const halfEvidence = 'half native full64/FLAGS/DF=1/canary outcomes=512; complete original STD/CLD source and all eight named half moves\n';
const halfOriginal = 'half actual original Go full64/FLAGS/DF=1/canary outcomes=512\n';

function logicalFPCompletion(ia32, original) {
  const arch = ia32 ? '386' : 'amd64';
  const rows = ia32 ? 6 : 8;
  const values = ia32 ? 96 : 128;
  const faults = ia32 ? 18 : 24;
  return original
    ? `logical FP actual original Go arch=${arch} rows=${rows} values=${values}; complete original FP divisor source and whole AX/DX/DF/canary observations\n`
    : `logical FP native arch=${arch} rows=${rows} values=${values} dead-division-faults=${faults}; whole AX/DX, DF and canaries; zero/overflow and signed-min/-1 SIGFPE\n`;
}

function requireIA32Images(output, staticCount, args) {
  const images = [...output.matchAll(/native oracle static IA32 ELF bytes=([1-9][0-9]*) sha256=([a-f0-9]{64})\b/g)];
  const direct = [...output.matchAll(/IA32 direct ELF bytes=([1-9][0-9]*) sha256=([a-f0-9]{64}) argv=(\[[^\r\n]*\])/g)];
  assert.equal(images.length, staticCount, 'missing complete static IA32 observations');
  assert.equal(direct.length, 1, 'missing direct IA32 execution');
  assert.equal(direct[0][3], args, 'wrong direct IA32 execution arguments');
  assert.equal(direct[0][1], images[0][1], 'direct IA32 image size changed');
  assert.equal(direct[0][2], images[0][2], 'direct IA32 image hash changed');
  assert.ok(images[0].index < direct[0].index, 'direct IA32 execution preceded image inspection');
  if (staticCount === 2) {
    assert.ok(direct[0].index < images[1].index, 'fault image inspection preceded value execution');
  }
  return {images, direct};
}

function requireSDKCommands(output) {
  const commands = [...output.matchAll(/actual executable=([^\r\n]+\/bin\/go) sha256=([a-f0-9]{64}) argv=(\[[^\r\n]*\])/g)];
  assert.equal(commands.length, 2, 'must observe the actual SDK version and original Go build');
  assert.equal(commands[0][1], commands[1][1], 'SDK executable changed');
  assert.equal(commands[0][2], commands[1][2], 'SDK hash changed');
  assert.equal(commands[0][3], '["version"]', 'actual SDK version was not observed');
  assert.match(commands[1][3], /^\["test" "-p=1" "-vet=off" "-c" "-o" "\/[^"\r\n]+\/original\.test" "\."\]$/,
    'original Go compile did not retain its complete actual SDK command');
  assert.ok(commands[0].index < commands[1].index, 'original Go build preceded actual SDK version');
  return commands;
}

function auditIntegerNativeFamilies(inventory, raw) {
  const result = auditNativeOwners(inventory, raw, roots, children);
  const states = new Map();
  const outputs = new Map([...roots, ...children].map(name => [name, '']));
  const spans = new Map(roots.map(root => [root, []]));
  const lastChildPass = new Map();
  let packageStarted = false, packageComplete = false;
  let nativeHosts = 0, sdkBuilds = 0, staticIA32Images = 0, directIA32Executions = 0;

  const events = raw.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
  for (const [sequence, event] of events.entries()) {
    assert.ok(!packageComplete, 'event after the complete native package');
    if (event.Action === 'build-output' && event.ImportPath && !event.Test) continue;
    if (!event.Test) {
      assert.ok(['start', 'output', 'pass'].includes(event.Action), 'unknown native package action');
      if (event.Action === 'start') {
        assert.ok(!packageStarted, 'duplicate native package start');
        packageStarted = true;
      } else {
        assert.ok(packageStarted, 'native event before package start');
        if (event.Action === 'output') assert.equal(typeof event.Output, 'string', 'package output must be text');
        if (event.Action === 'pass') packageComplete = true;
      }
      continue;
    }
    assert.ok(packageStarted, 'native test before package start');
    assert.ok(['run', 'output', 'pass'].includes(event.Action), 'unknown native test action');
    const root = event.Test.split('/')[0];
    const half = root.includes('MoveHalf');
    const logicalFP = root.includes('ImplicitDivideLogicalFP');
    const observed = root.includes('ImplicitDivide') || root.includes('SegmentQuery') || half;
    const ia32 = root.endsWith('386');
    if (event.Action === 'run') {
      states.set(event.Test, 'running');
      if (observed && event.Test !== root) {
        assert.equal([...outputs.get(root).matchAll(nativeHost)].length, 1,
          'integer axis lacks its preceding actual native host observation');
        assert.ok(!outputs.get(root).includes('actual executable='),
          'original Go compilation must follow all three native axes');
        if (half) {
          assert.equal(outputs.get(root).split(halfPreflight).length - 1, 1,
            'half axis lacks actual CPUID/XCR0 and native EVEX transport preflight');
        }
      }
      continue;
    }
    assert.equal(states.get(event.Test), 'running', 'native observation after its terminal');
    if (event.Action === 'output') {
      assert.equal(typeof event.Output, 'string', 'native output must be text');
      if (event.Test === root) {
        spans.get(root).push({offset: outputs.get(root).length, sequence});
      }
      outputs.set(event.Test, outputs.get(event.Test) + event.Output);
      continue;
    }
    states.set(event.Test, 'passed');
    if (event.Test !== root) {
      lastChildPass.set(root, sequence);
      if (root.includes('SegmentQuery')) {
        assert.equal(outputs.get(event.Test).split(segmentEvidence).length - 1, 1,
          'segment query axis lacks its complete opcode flags alias and fault evidence');
      }
      if (half) {
        assert.equal(outputs.get(event.Test).split(halfEvidence).length - 1, 1,
          'half axis lacks all 512 full64/FLAGS/DF/canary observations');
      }
      if (logicalFP) {
        assert.equal(outputs.get(event.Test).split(logicalFPCompletion(ia32, false)).length - 1, 1,
          'logical FP axis lacks complete native whole-register values and dead #DE execution');
      }
      if (ia32) {
        requireIA32Images(outputs.get(event.Test), 2, '[]');
        staticIA32Images += 2;
        directIA32Executions++;
      }
      continue;
    }
    if (!observed) continue;

    const output = outputs.get(root);
    const hosts = [...output.matchAll(nativeHost)];
    const commands = requireSDKCommands(output);
    assert.equal(hosts.length, 2, 'integer root must retain pre/post actual native host observations');
    assert.ok(hosts[0].index < commands[0].index && commands[0].index < commands[1].index &&
      commands[1].index < hosts[1].index, 'integer native/SDK observation order changed');
    if (half) {
      assert.equal(output.split(halfPreflight).length - 1, 1, 'duplicate or absent half native CPU preflight');
      assert.equal(output.split(halfOriginal).length - 1, 1, 'missing complete actual original Go DF observations');
      assert.ok(commands[1].index < output.indexOf(halfOriginal) && output.indexOf(halfOriginal) < hosts[1].index,
        'original Go DF terminal escaped its SDK/native host bracket');
    }
    if (logicalFP) {
      const completion = logicalFPCompletion(ia32, true);
      assert.equal(output.split(completion).length - 1, 1,
        'logical FP root lacks complete actual original Go value execution');
      assert.ok(commands[1].index < output.indexOf(completion) && output.indexOf(completion) < hosts[1].index,
        'original Go logical FP completion escaped its SDK/native host bracket');
    }

    // The SDK and final host observations occur after every execution child.
    // A printed root PASS before original Go execution cannot certify it.
    for (const observation of [commands[0], commands[1], hosts[1]]) {
      const preceding = spans.get(root).filter(span => span.offset <= observation.index);
      assert.ok(preceding[preceding.length - 1].sequence > lastChildPass.get(root),
        'original Go or final native host observation preceded the complete native axes');
    }
    if (ia32) {
      const observed = requireIA32Images(output, 1, originalArgs);
      assert.ok(commands[1].index < observed.images[0].index &&
        observed.direct[0].index < hosts[1].index, 'original Go IA32 execution escaped its native/SDK bracket');
      staticIA32Images++;
      directIA32Executions++;
    }
    // /proc/cpuinfo and maps are live observations, not stable identities.
    // CPU MHz and mappings may change; require both valid hashes, not equality.
    nativeHosts += hosts.length;
    sdkBuilds++;
  }
  return {...result, nativeHosts, sdkBuilds, staticIA32Images, directIA32Executions};
}

module.exports = {auditIntegerNativeFamilies, requireIA32Images, requireSDKCommands, roots, children};
if (require.main === module) {
  const directory = process.argv[2];
  const result = auditIntegerNativeFamilies(fs.readFileSync(path.join(directory, 'inventory.log'), 'utf8'),
    fs.readFileSync(path.join(directory, 'raw.jsonl'), 'utf8'));
  process.stdout.write(JSON.stringify(result) + '\n');
}
