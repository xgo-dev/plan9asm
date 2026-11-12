'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const auditor = require('./audit-packed-conversion-native.cjs');

test('native conversion receipts require a strict current-head owner and complete-union auditor', () => {
  const path = '.github/scripts/audit-packed-conversion-native.cjs';
  assert.ok(fs.existsSync(path), 'missing complete native conversion receipt auditor');
  const source = fs.readFileSync(path, 'utf8');
  for (const guard of ['auditNativeOwners', 'AVX512F=1 AVX512DQ=1 AVX512BW=1 AVX512VL=1 OSXSAVE=1',
    'PACKED_CONVERSION_NATIVE_F_DQ_BW_VL_OK', '0xe6n', 'original_go_named', 'original_go_raw']) {
    assert.ok(source.includes(guard), 'missing strict native conversion guard: ' + guard);
  }
});

// This independently constructs the expected semantic partitions and all
// actual run/pass events. Neither auditor metadata nor a success payload can
// supply the original Go, public API, backend or native hardware axes.
function fixture(owner) {
  const suffix = owner ? 'Part' + owner : '';
  const roots = [
    'TestCrossLinuxRuntimeMatrixX86PackedConversionNativeAVX512Status' + suffix,
    'TestCrossLinuxRuntimeMatrixX86PackedConversionNativeDeadFaults' + suffix,
  ];
  if (!owner) roots.push('TestCrossLinuxRuntimeMatrixX86PackedConversionNativeIndependentC');
  const children = [];
  for (let family = 0; family < 2; family++) {
    const size = family ? 222 : 692, limit = family ? 16 : 64;
    for (let start = owner * limit; start < size; start += 8 * limit) {
      const batch = roots[family] + '/batch-' + String(start).padStart(4, '0');
      children.push(batch);
      const originals = family ? ['original_go_opcode_reference'] : ['original_go_named', 'original_go_raw'];
      children.push(...originals.map(original => batch + '/' + original));
      for (const spelling of ['named', 'raw']) {
        const source = batch + '/' + spelling;
        children.push(source);
        for (const api of ['text', 'module', 'Go']) {
          const route = source + '/' + api;
          children.push(route, ...['backend_O0', 'backend_O2', 'IR_O2_backend_O2'].map(axis => route + '/' + axis));
        }
      }
    }
  }
  if (!owner) children.push(...['backend_O0', 'backend_O2', 'IR_O2_backend_O2'].map(axis => roots[2] + '/' + axis));
  const events = [];
  const packageName = 'github.com/xgo-dev/plan9asm';
  const emit = (action, name, output) => {
    const event = {Action: action, Package: packageName};
    if (name) event.Test = name;
    if (output !== undefined) event.Output = output;
    events.push(event);
  };
  function execute(name) {
    emit('run', name);
    if (roots.includes(name)) {
      emit('output', name, 'AVX512F=1 AVX512DQ=1 AVX512BW=1 AVX512VL=1 OSXSAVE=1 XCR0=e7\n');
      emit('output', name, 'PACKED_CONVERSION_NATIVE_F_DQ_BW_VL_OK\n');
    }
    for (const child of children.filter(child => child.slice(0, child.lastIndexOf('/')) === name)) execute(child);
    emit('pass', name);
  }
  for (const root of roots) execute(root);
  emit('pass');
  return {roots, children, inventory: roots.join('\n') + '\n', events};
}

function raw(events) {
  return events.map(event => JSON.stringify(event)).join('\n') + '\n';
}

test('all eight owners consume every complete original/public/native execution axis', () => {
  let roots = 0, children = 0;
  for (let owner = 0; owner < 8; owner++) {
    const independent = fixture(owner), expected = auditor.required(owner);
    assert.deepEqual(expected.roots, independent.roots);
    assert.deepEqual(expected.children, independent.children);
    const result = auditor.auditOwner(independent.inventory, raw(independent.events), owner);
    assert.equal(result.preflights, independent.roots.length);
    assert.equal(result.passed, independent.roots.length + independent.children.length);
    roots += result.roots;
    children += result.children;
  }
  assert.equal(roots, 17);
  assert.equal(children, 714);
});

test('failed skipped missing duplicate foreign incomplete and printed native receipts fail', () => {
  const base = fixture(0);
  const leaf = base.children.find(child => child.endsWith('/original_go_raw'));
  for (const action of ['fail', 'skip']) {
    const events = base.events.map(event => event.Test === leaf && event.Action === 'pass' ? {...event, Action: action} : event);
    assert.throws(() => auditor.auditOwner(base.inventory, raw(events), 0));
  }
  for (const alter of [
    events => events.filter(event => event.Test !== leaf),
    events => events.filter(event => !(event.Test === leaf && event.Action === 'pass')),
    events => [...events.slice(0, -1), {Action: 'pass', Package: 'github.com/xgo-dev/plan9asm', Test: leaf}, events.at(-1)],
    events => events.map(event => event.Test === leaf ? {...event, Test: event.Test + '/foreign'} : event),
    events => events.slice(0, -1),
    events => [{Action: 'output', Package: 'github.com/xgo-dev/plan9asm', Output: 'all native conversions passed\n'}, events.at(-1)],
  ]) assert.throws(() => auditor.auditOwner(base.inventory, raw(alter(base.events)), 0));
  assert.throws(() => auditor.auditOwner(base.inventory + 'TestForeign\n', raw(base.events), 0));
  assert.throws(() => auditor.auditOwner(base.inventory, raw(base.events), 1));
});

test('each current owner must observe all native features and enabled state before execution', () => {
  const base = fixture(1);
  for (const [before, after] of [
    ['AVX512F=1', 'AVX512F=0'], ['AVX512DQ=1', 'AVX512DQ=0'],
    ['AVX512BW=1', 'AVX512BW=0'], ['AVX512VL=1', 'AVX512VL=0'],
    ['OSXSAVE=1', 'OSXSAVE=0'], ['XCR0=e7', 'XCR0=c7'],
    ['PACKED_CONVERSION_NATIVE_F_DQ_BW_VL_OK', 'opcode_not_run'],
  ]) {
    const events = base.events.map(event => event.Output ? {...event, Output: event.Output.replace(before, after)} : event);
    assert.throws(() => auditor.auditOwner(base.inventory, raw(events), 1), before);
  }
  const late = base.events.filter(event => !event.Output);
  late.splice(late.length - 2, 0, ...base.events.filter(event => event.Output));
  assert.throws(() => auditor.auditOwner(base.inventory, raw(late), 1));
});

test('complete audit reopens all eight current-source raw streams instead of trusting summaries', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'packed-native-audit-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const head = 'a'.repeat(40), directories = [];
  for (let owner = 0; owner < 8; owner++) {
    const data = fixture(owner), child = path.join(directory, String(owner));
    fs.mkdirSync(child);
    fs.writeFileSync(path.join(child, 'context.json'), JSON.stringify({schema: 1, head, owner}));
    fs.writeFileSync(path.join(child, 'inventory.log'), data.inventory);
    fs.writeFileSync(path.join(child, 'raw.jsonl'), raw(data.events));
    directories.push(child);
  }
  assert.deepEqual(auditor.auditComplete(directories, head), {
    head, owners: 8, roots: 17, children: 714, passed: 731,
    valueKernels: 692, faultKernels: 222, skipped: 0, incomplete: 0,
  });
  assert.throws(() => auditor.auditComplete(directories.slice(0, -1), head));
  assert.throws(() => auditor.auditComplete([...directories.slice(0, -1), directories[0]], head));
  assert.throws(() => auditor.auditComplete(directories, 'b'.repeat(40)));
  const bad = path.join(directories[7], 'raw.jsonl');
  fs.writeFileSync(bad, '{"allPassed":true}\n');
  assert.throws(() => auditor.auditComplete(directories, head));
});
