'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {auditNativeOwners} = require('./audit-native-owners.cjs');
const {requireIA32Images} = require('./audit-integer-native-families.cjs');

const root = 'TestCrossLinuxRuntimeMatrixX86LeavePrivateEmitterWidthsAndFlags';
const architectures = ['amd64', '386'];
const pipelines = ['backend_O0', 'backend_O2', 'IR_O2/backend_O2'];
const groups = architectures.map(arch => root + '/' + arch);
const leaves = groups.flatMap(group => pipelines.map(pipeline => group + '/' + pipeline));
const children = [...groups, ...leaves];
const hostPrefix = 'IA32 direct host:';
const sdkPrefix = 'actual LEA source/object receipt:';
const markerPrefix = 'private LEAVE numerical completion arch=';
const host = /IA32 direct host: linux\/amd64 kernel=x86_64 CPUsha=[a-f0-9]{64} mapsha=[a-f0-9]{64}\b/g;

function requireSDK(output, arch) {
  const sdk = new RegExp('actual LEA source/object receipt: SDK=go[1-9][0-9]*\\.[0-9]+(?:\\.[0-9]+)?' +
    '(?:beta[0-9]+|rc[0-9]+)? target=linux/' + arch +
    ' source=[a-f0-9]{64} driver=[a-f0-9]{64} object=[a-f0-9]{64}\\b', 'g');
  assert.equal([...output.matchAll(sdk)].length, 1, 'private width lacks its actual SDK/source/object receipt');
  assert.equal(output.split(sdkPrefix).length - 1, 1, 'duplicate or malformed SDK capture');
}

// The fixed numerical contract is deliberately not an original Go/native
// stack ABI. Reuse the shared exact inventory, then bind every live owner to
// its real host, selected SDK, IA32 image and complete numerical execution.
function auditPrivateLEAVE(inventory, raw) {
  const result = auditNativeOwners(inventory, raw, [root], children);
  const outputs = new Map([root, ...children].map(name => [name, '']));
  const states = new Map();
  let started = false, complete = false;
  for (const line of raw.split(/\r?\n/).filter(Boolean)) {
    const event = JSON.parse(line);
    assert.ok(!complete, 'private LEAVE event after complete package');
    if (event.Action === 'build-output' && event.ImportPath && !event.Test) continue;
    if (!event.Test) {
      assert.ok(['start', 'output', 'pass'].includes(event.Action), 'unknown private-width package action');
      if (event.Action === 'start') {
        assert.ok(!started, 'duplicate private-width package start');
        started = true;
      } else {
        assert.ok(started, 'private-width output/terminal before package start');
        if (event.Action === 'output') assert.equal(typeof event.Output, 'string');
        if (event.Action === 'pass') complete = true;
      }
      continue;
    }
    assert.ok(started, 'private-width test before actual package start');
    assert.ok(['run', 'output', 'pass'].includes(event.Action), 'unknown private-width test action');
    const arch = event.Test.split('/')[1], group = root + '/' + arch;
    if (event.Action === 'run') {
      assert.ok(!states.has(event.Test), 'private-width test restarted after its first lifecycle');
      states.set(event.Test, 'running');
      if (event.Test !== root) {
        assert.equal([...outputs.get(root).matchAll(host)].length, 1, 'actual native host must precede every width');
        if (leaves.includes(event.Test)) requireSDK(outputs.get(group), arch);
      }
      continue;
    }
    assert.equal(states.get(event.Test), 'running', 'private-width observation outside live owner');
    if (event.Action === 'output') {
      assert.equal(typeof event.Output, 'string');
      outputs.set(event.Test, outputs.get(event.Test) + event.Output);
      if (event.Test === root && [...outputs.get(root).matchAll(host)].length > 1) {
        assert.ok(groups.every(group => states.get(group) === 'passed'), 'final host preceded a complete actual width');
      }
      continue;
    }
    states.set(event.Test, 'passed');
    const output = outputs.get(event.Test);
    if (event.Test === root) {
      assert.equal([...output.matchAll(host)].length, 2, 'private LEAVE requires actual native host brackets');
      assert.equal(output.split(hostPrefix).length - 1, 2, 'duplicate or malformed actual host');
      assert.ok(children.every(child => states.get(child) === 'passed'), 'root preceded a required numerical child');
      assert.ok(!output.includes(sdkPrefix) && !output.includes(markerPrefix), 'root summary cannot replace SDK/leaf observations');
    } else if (groups.includes(event.Test)) {
      requireSDK(output, arch);
      assert.ok(pipelines.every(pipeline => states.get(group + '/' + pipeline) === 'passed'), 'width parent preceded a real LLVM execution');
      assert.ok(!output.includes(hostPrefix) && !output.includes(markerPrefix) && !output.includes('IA32 ELF'),
        'width parent cannot replace actual host or leaf execution');
    } else {
      const marker = markerPrefix + arch + ': PRIVATE_LEAVE_128_WIDTH_VALUES_FLAGS_CANARIES_PASS\n';
      assert.equal(output.split(marker).length - 1, 1, 'missing or duplicate complete private-width execution');
      assert.equal(output.split(markerPrefix).length - 1, 1, 'foreign width or replacement marker');
      assert.ok(!output.includes(hostPrefix) && !output.includes(sdkPrefix), 'leaf cannot replace host or SDK owner');
      if (arch === '386') {
        const {direct} = requireIA32Images(output, 1, '[]');
        const commands = [...output.matchAll(/actual executable=([^\r\n]+) sha256=([a-f0-9]{64}) argv=\[\]/g)];
        assert.equal(commands.length, 1, 'missing actual static IA32 executable observation');
        assert.equal(commands[0][2], direct[0][2], 'actual IA32 executable hash changed');
        assert.ok(commands[0].index < direct[0].index && direct[0].index < output.indexOf(marker),
          'private IA32 completion preceded actual image execution');
      } else {
        assert.ok(!output.includes('IA32 ELF'), 'AMD64 execution cannot borrow an IA32 image');
      }
    }
  }
  return {...result, nativeHosts: 2, sdkCaptures: 2, llvmExecutions: 6,
    staticIA32Executions: 3, privateNumericalOnly: true};
}

module.exports = {auditPrivateLEAVE};
if (require.main === module) {
  const directory = process.argv[2];
  const result = auditPrivateLEAVE(fs.readFileSync(path.join(directory, 'inventory.log'), 'utf8'),
    fs.readFileSync(path.join(directory, 'raw.jsonl'), 'utf8'));
  process.stdout.write(JSON.stringify(result) + '\n');
}
