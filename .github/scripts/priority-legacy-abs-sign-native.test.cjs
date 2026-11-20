'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');

// Independent execution denominator, not imported from the auditor.
const roots = ['TestCrossLinuxRuntimeMatrixX86LegacyAbsSignOriginalAlignmentFaultsAMD64',
  'TestCrossLinuxRuntimeMatrixX86LegacyAbsSignOriginalAlignmentFaults386'];
const axes = ['backend_O0', 'backend_O2', 'IR_O2_backend_O2'];
const operations = ['PABSB', 'PABSW', 'PABSD', 'PSIGNB', 'PSIGNW', 'PSIGND',
  'VPABSB', 'VPABSW', 'VPABSD', 'VPSIGNB', 'VPSIGNW', 'VPSIGND'];
const roles = ['live', 'dead'];
const children = roots.flatMap(root => axes.flatMap(axis => [root + '/' + axis,
  ...operations.flatMap(op => roles.map(role => root + '/' + axis + '/' + op + '/' + role))]));
const inventory = roots.join('\n') + '\nok\tgithub.com/xgo-dev/plan9asm\n';
const digest = 'a'.repeat(64);
const host = `IA32 direct host: linux/amd64 kernel=x86_64 CPUsha=${digest} mapsha=${digest}\n`;
const preflight = 'ABS/sign actual native SSSE3=1 AVX=1\n';
const marker = 'ABS/sign original Go bytes and LLVM native alignment/access/CF/MXCSR=0x1f80/canary probes 20 failures 0\n';
const image = `native oracle static IA32 ELF bytes=4096 sha256=${digest}\n`;
const sdk = arch => `actual LEA source/object receipt: SDK=go1.27.2 target=linux/${arch} source=${digest} driver=${digest} object=${digest}\n`;
const event = (Action, Test, Output) => ({Action, Package: 'github.com/xgo-dev/plan9asm',
  ...(Test ? {Test} : {}), ...(Output !== undefined ? {Output} : {})});
const serialize = events => events.map(value => JSON.stringify(value)).join('\n');

function completeEvents() {
  const events = [event('start')];
  for (const root of roots) {
    const arch = root.endsWith('386') ? '386' : 'amd64';
    events.push(event('run', root), event('output', root, host + preflight + sdk(arch)));
    for (const axis of axes) {
      const parent = root + '/' + axis;
      events.push(event('run', parent));
      if (arch === '386') events.push(event('output', parent, image));
      for (const op of operations) for (const role of roles) {
        const leaf = parent + '/' + op + '/' + role;
        events.push(event('run', leaf), event('output', leaf, marker), event('pass', leaf));
      }
      events.push(event('pass', parent));
    }
    events.push(event('output', root, host), event('pass', root));
  }
  events.push(event('pass'));
  return events;
}

function audit(events = completeEvents(), discovered = inventory) {
  const filename = '.github/scripts/audit-legacy-abs-sign-native.cjs';
  assert.ok(fs.existsSync(filename), 'original legacy alignment faults lack their required exact native auditor');
  return require('./audit-legacy-abs-sign-native.cjs').auditLegacyAbsSignNative(discovered, serialize(events));
}

test('legacy ABS/sign native owner requires 144 complete live/dead kernel executions and 5760 direct probes', () => {
  assert.deepEqual(audit(), {roots: 2, children: 150, passed: 152, skipped: 0, incomplete: 0,
    nativeHosts: 4, sdkCaptures: 2, isaPreflights: 2, staticIA32Images: 3,
    kernelExecutions: 144, directProbeProcesses: 5760});
});

test('legacy ABS/sign rejects every missing duplicated failed skipped or unfinished lifecycle', () => {
  audit();
  for (const name of [...roots, ...children]) {
    for (const Action of ['fail', 'skip']) {
      assert.throws(() => audit(completeEvents().map(value => value.Test === name && value.Action === 'pass'
        ? {...value, Action} : value)), name + Action);
    }
    for (const Action of ['run', 'pass']) {
      const original = completeEvents();
      const at = original.findIndex(value => value.Action === Action && value.Test === name);
      assert.throws(() => audit(original.filter((_, index) => index !== at)), name + ' missing ' + Action);
      original.splice(at, 0, original[at]);
      assert.throws(() => audit(original), name + ' duplicate ' + Action);
    }
    const late = completeEvents();
    const at = late.findIndex(value => value.Action === 'pass' && value.Test === name);
    late.splice(at + 1, 0, event('output', name, 'late output\n'));
    assert.throws(() => audit(late), name + ' output after terminal');
  }
});

test('legacy ABS/sign rejects changed native inventory package lifecycle and printed summaries', () => {
  audit();
  for (const discovered of ['', inventory + roots[0] + '\n', inventory.replace(roots[1], 'TestObjectOnly')]) {
    assert.throws(() => audit(completeEvents(), discovered));
  }
  for (const events of [completeEvents().slice(1), completeEvents().slice(0, -1),
    [...completeEvents(), event('pass')], [event('start'), ...completeEvents()],
    [event('output', undefined, '144 kernels passed')],
    completeEvents().map(value => ({...value, Package: 'foreign/package'}))]) assert.throws(() => audit(events));
});

test('legacy ABS/sign binds each actual 20-probe completion marker to its own live kernel', () => {
  audit();
  for (const name of children.filter(name => name.endsWith('/live') || name.endsWith('/dead'))) {
    for (const replacement of ['', marker + marker, marker.replace('20', '19'), marker.replace('failures 0', 'failures 1'),
      marker.replace('MXCSR=0x1f80', 'MXCSR=inherited'), marker.replace('MXCSR=0x1f80', 'MXCSR=0x21f80'),
      host + marker, preflight + marker, sdk('amd64') + marker, image + marker]) {
      assert.throws(() => audit(completeEvents().map(value => value.Test === name && value.Output
        ? {...value, Output: value.Output.replace(marker, replacement)} : value)), name);
    }
  }
  const misplaced = completeEvents().map(value => value.Test === roots[0] + '/backend_O0/PABSB/live' && value.Output
    ? {...value, Test: roots[0] + '/backend_O0'} : value);
  assert.throws(() => audit(misplaced), 'axis summary cannot replace an executed kernel');
});

test('legacy ABS/sign requires actual host ISA and original SDK object before every axis', () => {
  audit();
  for (const root of roots) {
    const arch = root.endsWith('386') ? '386' : 'amd64';
    for (const needle of [host, preflight, sdk(arch)]) {
      for (const replacement of ['', needle + needle, needle.replace('kernel=x86_64', 'kernel=aarch64'),
        needle.replace('SSSE3=1', 'SSSE3=0'), needle.replace('AVX=1', 'AVX=0'),
        needle.replace(digest, 'invalid'), needle.replace('linux/' + arch, 'linux/arm64')]) {
        if (needle === replacement) continue;
        assert.throws(() => audit(completeEvents().map(value => value.Test === root && value.Output
          ? {...value, Output: value.Output.replace(needle, replacement)} : value)), needle);
      }
    }
    const earlyPost = completeEvents();
    const post = earlyPost.findLastIndex(value => value.Test === root && value.Output === host);
    const [observation] = earlyPost.splice(post, 1);
    const beforeLast = earlyPost.findIndex(value => value.Test === root + '/' + axes[2] && value.Action === 'pass');
    earlyPost.splice(beforeLast, 0, observation);
    assert.throws(() => audit(earlyPost), 'final native host must follow all complete axes');
    const earlyAxis = completeEvents();
    const first = earlyAxis.findIndex(value => value.Test === root && value.Output?.includes(preflight));
    const output = earlyAxis[first].Output;
    earlyAxis[first] = event('output', root, host + preflight);
    earlyAxis.splice(first + 2, 0, event('output', root, sdk(arch)));
    assert.throws(() => audit(earlyAxis), 'SDK capture cannot follow an axis start');
    assert.ok(output.includes(sdk(arch)));
  }
});

test('legacy ABS/sign every mode32 axis binds a complete static native image before its first kernel', () => {
  audit();
  const root = roots[1];
  for (const axis of axes) {
    const parent = root + '/' + axis;
    for (const replacement of ['', image + image, image.replace('4096', '0'),
      image.replace(digest, 'invalid'), image.replace('static IA32', 'QEMU translated')]) {
      assert.throws(() => audit(completeEvents().map(value => value.Test === parent && value.Output
        ? {...value, Output: value.Output.replace(image, replacement)} : value)), parent);
    }
    const late = completeEvents();
    const at = late.findIndex(value => value.Test === parent && value.Output === image);
    const [observation] = late.splice(at, 1);
    late.splice(at + 2, 0, observation);
    assert.throws(() => audit(late), 'IA32 image cannot be first inspected after execution');
  }
});
