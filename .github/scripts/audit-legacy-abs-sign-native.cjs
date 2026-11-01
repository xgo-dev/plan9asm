'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {auditNativeOwners} = require('./audit-native-owners.cjs');

const roots = ['TestCrossLinuxRuntimeMatrixX86LegacyAbsSignOriginalAlignmentFaultsAMD64',
  'TestCrossLinuxRuntimeMatrixX86LegacyAbsSignOriginalAlignmentFaults386'];
const axes = ['backend_O0', 'backend_O2', 'IR_O2_backend_O2'];
const operations = ['PABSB', 'PABSW', 'PABSD', 'PSIGNB', 'PSIGNW', 'PSIGND',
  'VPABSB', 'VPABSW', 'VPABSD', 'VPSIGNB', 'VPSIGNW', 'VPSIGND'];
const roles = ['live', 'dead'];
const parents = roots.flatMap(root => axes.map(axis => root + '/' + axis));
const leaves = parents.flatMap(parent => operations.flatMap(op => roles.map(role => parent + '/' + op + '/' + role)));
const children = [...parents, ...leaves];
const marker = 'ABS/sign original Go bytes and LLVM native alignment/access/CF/MXCSR=0x1f80/canary probes 20 failures 0\n';
const preflight = 'ABS/sign actual native SSSE3=1 AVX=1\n';
const hostPrefix = 'IA32 direct host:';
const sdkPrefix = 'actual LEA source/object receipt:';
const imagePrefix = 'native oracle static IA32 ELF';
const host = /IA32 direct host: linux\/amd64 kernel=x86_64 CPUsha=[a-f0-9]{64} mapsha=[a-f0-9]{64}\b/g;
const image = /native oracle static IA32 ELF bytes=[1-9][0-9]* sha256=[a-f0-9]{64}\b/g;

function auditLegacyAbsSignNative(inventory, raw) {
  const result = auditNativeOwners(inventory, raw, roots, children);
  const outputs = new Map([...roots, ...children].map(name => [name, '']));
  const states = new Map(), passed = new Map();
  const spans = new Map(roots.map(root => [root, []]));
  let started = false, complete = false, kernelExecutions = 0;

  function rootObservations(root, final) {
    const output = outputs.get(root), arch = root.endsWith('386') ? '386' : 'amd64';
    const captures = [...output.matchAll(new RegExp('actual LEA source/object receipt: SDK=go[1-9][0-9]*\\.[0-9]+(?:\\.[0-9]+)?(?:beta[0-9]+|rc[0-9]+)? target=linux/' + arch +
      ' source=[a-f0-9]{64} driver=[a-f0-9]{64} object=[a-f0-9]{64}\\b', 'g'))];
    const hosts = [...output.matchAll(host)];
    assert.equal(hosts.length, final ? 2 : 1, 'missing or duplicated actual native host bracket');
    assert.equal(output.split(hostPrefix).length - 1, hosts.length, 'malformed extra native host');
    assert.equal(captures.length, 1, 'missing unique actual original Go SDK/source/object capture');
    assert.equal(output.split(sdkPrefix).length - 1, 1, 'malformed extra SDK/source/object capture');
    assert.equal(output.split(preflight).length - 1, 1, 'missing or duplicated actual SSSE3/AVX preflight');
    assert.equal(output.split('ABS/sign actual native').length - 1, 1, 'malformed extra CPU preflight');
    assert.ok(hosts[0].index < output.indexOf(preflight) && output.indexOf(preflight) < captures[0].index,
      'CPU or original source capture escaped the actual native host bracket');
    assert.ok(!output.includes(marker) && !output.includes(imagePrefix), 'root summaries cannot replace executed kernels or axis-owned images');
    if (final) {
      assert.ok(captures[0].index < hosts[1].index, 'final native host preceded original source capture');
      const span = spans.get(root).filter(value => value.offset <= hosts[1].index).pop();
      for (const axis of axes) {
        assert.ok(passed.has(root + '/' + axis), 'root lacks its complete native optimization axis');
        assert.ok(span && span.sequence > passed.get(root + '/' + axis), 'final native host preceded an execution axis');
      }
    }
  }

  for (const [sequence, line] of raw.split(/\r?\n/).filter(Boolean).entries()) {
    const event = JSON.parse(line);
    assert.ok(!complete, 'event after complete native ABS/sign package');
    if (event.Action === 'build-output' && event.ImportPath && !event.Test) continue;
    if (!event.Test) {
      assert.ok(['start', 'output', 'pass'].includes(event.Action), 'unknown ABS/sign package lifecycle');
      if (event.Action === 'start') {
        assert.ok(!started, 'duplicate ABS/sign package start');
        started = true;
      } else {
        assert.ok(started, 'package observation before actual start');
        if (event.Action === 'output') assert.equal(typeof event.Output, 'string', 'nontext package output');
        if (event.Action === 'pass') complete = true;
      }
      continue;
    }
    assert.ok(started, 'native ABS/sign test before package start');
    assert.ok(['run', 'output', 'pass'].includes(event.Action), 'unknown ABS/sign test lifecycle');
    const root = event.Test.split('/')[0];
    if (event.Action === 'run') {
      assert.ok(!states.has(event.Test), 'native ABS/sign lifecycle restarted');
      states.set(event.Test, 'running');
      if (event.Test !== root) rootObservations(root, false);
      if (leaves.includes(event.Test) && root.endsWith('386')) {
        const parent = event.Test.split('/').slice(0, 2).join('/');
        assert.equal([...outputs.get(parent).matchAll(image)].length, 1,
          'IA32 kernel started before its complete static image inspection');
      }
      continue;
    }
    assert.equal(states.get(event.Test), 'running', 'ABS/sign observation outside its live owner');
    if (event.Action === 'output') {
      assert.equal(typeof event.Output, 'string', 'nontext ABS/sign test output');
      if (event.Test === root) spans.get(root).push({offset: outputs.get(root).length, sequence});
      outputs.set(event.Test, outputs.get(event.Test) + event.Output);
      continue;
    }
    states.set(event.Test, 'passed');
    passed.set(event.Test, sequence);
    if (event.Test === root) {
      rootObservations(root, true);
      continue;
    }
    const output = outputs.get(event.Test);
    for (const foreign of [hostPrefix, sdkPrefix, 'ABS/sign actual native']) {
      assert.ok(!output.includes(foreign), 'child cannot replace actual root host/SDK/ISA ownership');
    }
    if (parents.includes(event.Test)) {
      assert.ok(!output.includes(marker), 'axis summary cannot replace actual kernel execution');
      const count = root.endsWith('386') ? 1 : 0;
      assert.equal([...output.matchAll(image)].length, count, 'axis lacks its exact complete native static image');
      assert.equal(output.split(imagePrefix).length - 1, count, 'malformed extra IA32 static image');
      for (const op of operations) for (const role of roles) {
        assert.ok(passed.has(event.Test + '/' + op + '/' + role), 'axis ended before its entire live/dead opcode family');
      }
    } else {
      assert.ok(!output.includes(imagePrefix), 'kernel cannot replace axis-owned image authentication');
      assert.equal(output.split(marker).length - 1, 1, 'kernel lacks exactly one actual complete 20-probe observation');
      kernelExecutions++;
    }
  }
  return {...result, nativeHosts: 4, sdkCaptures: 2, isaPreflights: 2, staticIA32Images: 3,
    kernelExecutions, directProbeProcesses: kernelExecutions * 20 * 2};
}

module.exports = {auditLegacyAbsSignNative};
if (require.main === module) {
  const directory = process.argv[2];
  process.stdout.write(JSON.stringify(auditLegacyAbsSignNative(
    fs.readFileSync(path.join(directory, 'inventory.log'), 'utf8'),
    fs.readFileSync(path.join(directory, 'raw.jsonl'), 'utf8'))) + '\n');
}
