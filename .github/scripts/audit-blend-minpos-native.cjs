'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {auditNativeOwners} = require('./audit-native-owners.cjs');

const roots = ['TestCrossLinuxRuntimeMatrixX86BlendMinposOriginalFaultsAMD64',
  'TestCrossLinuxRuntimeMatrixX86BlendMinposOriginalFaults386'];
const axes = ['backend_O0', 'backend_O2', 'IR_O2_backend_O2'];
const forms = [['BLENDVPS', 'X'], ['VBLENDVPS', 'X'], ['VBLENDVPS', 'Y'],
  ['BLENDVPD', 'X'], ['VBLENDVPD', 'X'], ['VBLENDVPD', 'Y'],
  ['PBLENDVB', 'X'], ['VPBLENDVB', 'X'], ['VPBLENDVB', 'Y'],
  ['PHMINPOSUW', 'X'], ['VPHMINPOSUW', 'X']];
const parents = roots.flatMap(root => axes.map(axis => root + '/' + axis));
const leaves = parents.flatMap(parent => forms.flatMap(([op, bank]) => ['live', 'dead'].flatMap(role =>
  [0, 1].map(zero => `${parent}/${op}/${bank}/${role}/maskzero=${zero}`))));
const children = [...parents, ...leaves];
const leafSet = new Set(leaves), parentSet = new Set(parents);
const marker = 'blend/minimum original Go bytes and LLVM native alignment/access/CF/MXCSR=0x1f80/canary probes 20 failures 0\n';
const preflight = 'blend/minimum actual native SSE4.1=1 AVX2=1\n';
const hostPrefix = 'IA32 direct host:', sdkPrefix = 'actual LEA source/object receipt:';
const imagePrefix = 'native oracle static IA32 ELF';
const host = /IA32 direct host: linux\/amd64 kernel=x86_64 CPUsha=[a-f0-9]{64} mapsha=[a-f0-9]{64}\b/g;
const image = /native oracle static IA32 ELF bytes=[1-9][0-9]* sha256=[a-f0-9]{64}\b/g;

// These 22 minimum-ISA functions and 44 live/dead/mask cases are actual
// original-byte fault execution, not the 78-program private mathematical
// companion or its virtual Z/Y/X alias observations.
function auditBlendMinposNative(inventory, raw) {
  const events = raw.split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
  // The shared owner checker closes the root/axis topology. Keep the 264
  // fixed leaves in the stricter linear protocol below: feeding every leaf
  // into its all-ancestors loop would make exhaustive negative audits O(n²).
  const ancestry = events.filter(event => !leafSet.has(event.Test));
  auditNativeOwners(inventory, ancestry.map(event => JSON.stringify(event)).join('\n'), roots, parents);
  const outputs = new Map([...roots, ...children].map(name => [name, '']));
  const states = new Map(), passed = new Map();
  const spans = new Map(roots.map(root => [root, []]));
  let started = false, complete = false, driver = '', kernelExecutions = 0;

  function rootObservations(root, final) {
    const output = outputs.get(root), arch = root.endsWith('386') ? '386' : 'amd64';
    const capture = new RegExp('actual LEA source/object receipt: SDK=go1\\.27\\.2 target=linux/' + arch +
      ' source=[a-f0-9]{64} driver=([a-f0-9]{64}) object=[a-f0-9]{64}\\b', 'g');
    const captures = [...output.matchAll(capture)], hosts = [...output.matchAll(host)];
    assert.equal(hosts.length, final ? 2 : 1, 'missing or duplicated direct native host bracket');
    assert.equal(output.split(hostPrefix).length - 1, hosts.length, 'malformed extra native host');
    assert.equal(captures.length, 1, 'missing unique actual Go1.27.2 source/object receipt');
    assert.equal(output.split(sdkPrefix).length - 1, 1, 'malformed extra SDK source/object receipt');
    if (!driver) driver = captures[0][1];
    assert.equal(captures[0][1], driver, 'native owners used different actual Go drivers');
    assert.equal(output.split(preflight).length - 1, 1, 'missing complete actual SSE4.1/AVX2 preflight');
    assert.equal(output.split('blend/minimum actual native').length - 1, 1, 'malformed extra native ISA preflight');
    assert.ok(hosts[0].index < output.indexOf(preflight) && output.indexOf(preflight) < captures[0].index,
      'ISA/source capture escaped the actual native host bracket');
    assert.ok(!output.includes(marker) && !output.includes(imagePrefix),
      'root summary cannot replace actual leaf execution or axis-owned images');
    if (final) {
      assert.ok(captures[0].index < hosts[1].index, 'final host preceded original source capture');
      const span = spans.get(root).filter(value => value.offset <= hosts[1].index).pop();
      for (const axis of axes) {
        assert.ok(passed.has(root + '/' + axis), 'native root lacks a complete optimization axis');
        assert.ok(span && span.sequence > passed.get(root + '/' + axis), 'final host preceded an execution axis');
      }
    }
  }

  for (const [sequence, event] of events.entries()) {
    assert.ok(!complete, 'event after complete blend/minimum package');
    if (event.Action === 'build-output' && event.ImportPath && !event.Test) continue;
    assert.equal(event.Package, 'github.com/xgo-dev/plan9asm', 'foreign native package');
    if (!event.Test) {
      assert.ok(['start', 'output', 'pass'].includes(event.Action), 'unknown native package lifecycle');
      if (event.Action === 'start') {
        assert.ok(!started, 'duplicate native package start');
        started = true;
      } else {
        assert.ok(started, 'observation before native package start');
        if (event.Action === 'output') assert.equal(typeof event.Output, 'string', 'nontext package output');
        if (event.Action === 'pass') complete = true;
      }
      continue;
    }
    assert.ok(started, 'native test before package start');
    assert.ok(['run', 'output', 'pass'].includes(event.Action), 'unknown native test lifecycle');
    const root = event.Test.split('/')[0];
    if (leafSet.has(event.Test)) {
      const parent = event.Test.split('/').slice(0, 2).join('/');
      assert.equal(states.get(root), 'running', 'leaf outside its live root');
      assert.equal(states.get(parent), 'running', 'leaf outside its live optimization axis');
    }
    if (event.Action === 'run') {
      assert.ok(!states.has(event.Test), 'native test lifecycle restarted');
      states.set(event.Test, 'running');
      if (event.Test !== root) rootObservations(root, false);
      if (leafSet.has(event.Test) && root.endsWith('386')) {
        const parent = event.Test.split('/').slice(0, 2).join('/');
        assert.equal([...outputs.get(parent).matchAll(image)].length, 1,
          'IA32 leaf started before its complete static image inspection');
      }
      continue;
    }
    assert.equal(states.get(event.Test), 'running', 'observation outside its live native owner');
    if (event.Action === 'output') {
      assert.equal(typeof event.Output, 'string', 'nontext native output');
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
    for (const foreign of [hostPrefix, sdkPrefix, 'blend/minimum actual native']) {
      assert.ok(!output.includes(foreign), 'child cannot replace actual root host/SDK/ISA ownership');
    }
    if (parentSet.has(event.Test)) {
      assert.ok(!output.includes(marker), 'axis summary cannot replace actual completed kernels');
      const count = root.endsWith('386') ? 1 : 0;
      assert.equal([...output.matchAll(image)].length, count, 'axis lacks its exact native static image');
      assert.equal(output.split(imagePrefix).length - 1, count, 'malformed extra IA32 static image');
      for (const leaf of leaves.filter(name => name.startsWith(event.Test + '/'))) {
        assert.ok(passed.has(leaf), 'axis ended before its complete opcode/width/live/dead/mask family');
      }
    } else {
      assert.ok(!output.includes(imagePrefix), 'leaf cannot replace its axis-owned IA32 image');
      assert.equal(output.split(marker).length - 1, 1, 'leaf lacks exactly one complete original/translated 20-probe observation');
      assert.equal(output.split('blend/minimum original Go bytes').length - 1, 1, 'malformed extra leaf completion');
      kernelExecutions++;
    }
  }
  assert.equal(passed.size, roots.length + children.length, 'incomplete actual root/axis/leaf inventory');
  return {roots: roots.length, children: children.length, passed: passed.size, skipped: 0, incomplete: 0,
    nativeHosts: 4, sdkCaptures: 2, isaPreflights: 2, staticIA32Images: 3,
    kernelExecutions, pairedProbes: kernelExecutions * 20, directProbeProcesses: kernelExecutions * 40};
}

module.exports = {auditBlendMinposNative};
if (require.main === module) {
  const directory = process.argv[2];
  process.stdout.write(JSON.stringify(auditBlendMinposNative(
    fs.readFileSync(path.join(directory, 'inventory.log'), 'utf8'),
    fs.readFileSync(path.join(directory, 'raw.jsonl'), 'utf8'))) + '\n');
}
