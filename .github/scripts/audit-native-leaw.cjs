'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {auditNativeOwners} = require('./audit-native-owners.cjs');

const root = 'TestCrossLinuxRuntimeMatrixX86LEAWRetainedPointerOriginalBytesAndNativeDF';
const apis = ['text', 'module', 'Go'];
const pipelines = ['backend_O0', 'backend_O2', 'IR_O2/backend_O2'];
const groups = apis.map(api => root + '/' + api);
const leaves = groups.flatMap(group => pipelines.map(pipeline => group + '/' + pipeline));
const original = root + '/OriginalGoBytes';
const children = [...groups, ...leaves, original];
const llvmMarker = 'native retained LEAW LLVM execution: LEAW_RETAINED_POINTER_300_VALUES_STATUS_CANARIES_PASS\n';
const originalMarker = 'native retained LEAW actual Go bytes execution: LEAW_RETAINED_POINTER_300_VALUES_STATUS_CANARIES_PASS\n';
const hostPrefix = 'IA32 direct host:';
const sdkPrefix = 'actual LEA source/object receipt:';
const host = /IA32 direct host: linux\/amd64 kernel=x86_64 CPUsha=[a-f0-9]{64} mapsha=[a-f0-9]{64}\b/g;
const sdk = /actual LEA source\/object receipt: SDK=go[1-9][0-9]*\.[0-9]+(?:\.[0-9]+)?(?:beta[0-9]+|rc[0-9]+)? target=linux\/amd64 source=[a-f0-9]{64} driver=[a-f0-9]{64} object=[a-f0-9]{64}\b/g;

function auditNativeLEAW(inventory, raw) {
  const result = auditNativeOwners(inventory, raw, [root], children);
  const outputs = new Map([root, ...children].map(name => [name, '']));
  const passed = new Map(), states = new Map(), spans = [];
  let started = false, complete = false;
  for (const [sequence, line] of raw.split(/\r?\n/).filter(Boolean).entries()) {
    const event = JSON.parse(line);
    assert.ok(!complete, 'event after the complete LEAW package');
    if (event.Action === 'build-output' && event.ImportPath && !event.Test) continue;
    if (!event.Test) {
      assert.ok(['start', 'output', 'pass'].includes(event.Action), 'unknown LEAW package lifecycle action');
      if (event.Action === 'start') {
        assert.ok(!started, 'duplicate LEAW package start');
        started = true;
      } else {
        assert.ok(started, 'LEAW package observation before its start');
        if (event.Action === 'output') assert.equal(typeof event.Output, 'string', 'package output must be text');
        if (event.Action === 'pass') complete = true;
      }
      continue;
    }
    assert.ok(started, 'LEAW test before its package start');
    assert.ok(['run', 'output', 'pass'].includes(event.Action), 'unknown LEAW test lifecycle action');
    if (event.Action === 'run') {
      assert.ok(!states.has(event.Test), 'LEAW test restarted after its original lifecycle');
      states.set(event.Test, 'running');
      if (event.Test !== root) {
        const output = outputs.get(root);
        const hosts = [...output.matchAll(host)], captures = [...output.matchAll(sdk)];
        assert.equal(hosts.length, 1, 'LEAW child lacks its preceding actual native host');
        assert.equal(captures.length, 1, 'LEAW child lacks its preceding actual SDK/source/object capture');
        assert.ok(hosts[0].index < captures[0].index, 'SDK capture preceded actual native host identity');
        if (event.Test === original) {
          for (const group of groups) assert.ok(passed.has(group), 'original bytes preceded a complete API group');
        }
      }
      continue;
    }
    assert.equal(states.get(event.Test), 'running', 'LEAW observation outside its live execution owner');
    if (event.Action === 'output') {
      assert.equal(typeof event.Output, 'string', 'LEAW output must be text');
      if (event.Test === root) spans.push({offset: outputs.get(root).length, sequence});
      outputs.set(event.Test, outputs.get(event.Test) + event.Output);
      continue;
    }
    states.set(event.Test, 'passed');
    passed.set(event.Test, sequence);
    const output = outputs.get(event.Test);
    if (event.Test !== root) {
      assert.ok(!output.includes(hostPrefix) && !output.includes(sdkPrefix), 'child cannot replace root host/SDK ownership');
      if (groups.includes(event.Test)) {
        for (const pipeline of pipelines) assert.ok(passed.has(event.Test + '/' + pipeline), 'API parent preceded an executed LLVM leaf');
        assert.ok(!output.includes(llvmMarker) && !output.includes(originalMarker), 'API parent cannot replace a leaf execution');
      } else {
        const marker = event.Test === original ? originalMarker : llvmMarker;
        const foreign = event.Test === original ? llvmMarker : originalMarker;
        assert.equal(output.split(marker).length - 1, 1, 'missing or duplicated complete actual LEAW execution marker');
        assert.ok(!output.includes(foreign), 'LLVM and actual Go bytes are separate execution obligations');
      }
      continue;
    }
    const hosts = [...output.matchAll(host)], captures = [...output.matchAll(sdk)];
    assert.equal(hosts.length, 2, 'LEAW requires actual native pre/post host observations');
    assert.equal(output.split(hostPrefix).length - 1, 2, 'malformed extra native host receipt');
    assert.equal(captures.length, 1, 'LEAW requires its unique actual SDK/source/object capture');
    assert.equal(output.split(sdkPrefix).length - 1, 1, 'malformed extra SDK capture');
    assert.ok(hosts[0].index < captures[0].index && captures[0].index < hosts[1].index, 'SDK capture escaped native host brackets');
    for (const child of children) assert.ok(passed.has(child), 'root preceded a required execution child');
    const finalSpan = spans.filter(span => span.offset <= hosts[1].index).pop();
    assert.ok(finalSpan && finalSpan.sequence > passed.get(original), 'final host preceded actual original-byte execution');
    assert.ok(!output.includes(llvmMarker) && !output.includes(originalMarker), 'root summary cannot replace leaf execution');
  }
  return {...result, nativeHosts: 2, sdkCaptures: 1, llvmExecutions: 9, originalByteExecutions: 1};
}

module.exports = {auditNativeLEAW};
if (require.main === module) {
  const directory = process.argv[2];
  const result = auditNativeLEAW(fs.readFileSync(path.join(directory, 'inventory.log'), 'utf8'),
    fs.readFileSync(path.join(directory, 'raw.jsonl'), 'utf8'));
  process.stdout.write(JSON.stringify(result) + '\n');
}
