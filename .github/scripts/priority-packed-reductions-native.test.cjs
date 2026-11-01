'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const auditor = require('./audit-packed-reduction-native.cjs');

test('native reduction receipts require all current source execution and CPU evidence', () => {
  const path = '.github/scripts/audit-packed-reduction-native.cjs';
  assert.ok(fs.existsSync(path), 'missing complete native reduction receipt auditor');
  const source = fs.readFileSync(path, 'utf8');
  for (const required of [
    'auditNativeOwners', 'SSE3=1 SSE41=1 AVX=1 OSXSAVE=1',
    'PACKED_REDUCTION_NATIVE_SSE3_SSE41_AVX_OK', '6n',
    'original_go_named', 'original_go_raw', 'original_go_opcode_reference',
    'backend_O0', 'backend_O2', 'IR_O2_backend_O2',
  ]) {
    assert.ok(source.includes(required), 'missing strict native reduction guard: ' + required);
  }
});

// Synthetic raw streams test only the auditor. Actual CPU/Go/LLVM execution
// remains required in the separate native jobs; this is not such a receipt.
function fixture(owner) {
  const roots = ['Values', 'DeadFaults'].map(family =>
    'TestCrossLinuxRuntimeMatrixX86PackedReductionNative' + family + 'Part' + owner);
  const children = [];
  for (let family = 0; family < 2; family++) {
    const count = family ? 37 : 258, limit = family ? 8 : 64;
    for (let start = owner * limit; start < count; start += 4 * limit) {
      const batch = roots[family] + '/batch-' + String(start).padStart(4, '0');
      const originals = family ? ['original_go_opcode_reference'] : ['original_go_named', 'original_go_raw'];
      children.push(batch, ...originals.map(original => batch + '/' + original));
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
  const events = [];
  const emit = (Action, Test, Output) => {
    const event = {Action, Package: 'github.com/xgo-dev/plan9asm'};
    if (Test) event.Test = Test;
    if (Output !== undefined) event.Output = Output;
    events.push(event);
  };
  function execute(name) {
    emit('run', name);
    if (roots.includes(name)) {
      emit('output', name, 'SSE3=1 SSE41=1 AVX=1 OSXSAVE=1 XCR0=7\n');
      emit('output', name, 'PACKED_REDUCTION_NATIVE_SSE3_SSE41_AVX_OK members=fff\n');
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

test('all four owner pairs retain the complete Go source, public API and pipeline axes', () => {
  let roots = 0, children = 0;
  for (let owner = 0; owner < 4; owner++) {
    const independent = fixture(owner), expected = auditor.required(owner);
    assert.deepEqual(expected.roots, independent.roots);
    assert.deepEqual(expected.children, independent.children);
    const result = auditor.auditOwner(independent.inventory, raw(independent.events), owner);
    assert.equal(result.preflights, 2);
    assert.equal(result.passed, independent.roots.length + independent.children.length);
    roots += result.roots;
    children += result.children;
  }
  assert.equal(roots, 8);
  assert.equal(children, 285);
});

test('failed skipped missing duplicated foreign incomplete and printed receipts fail', () => {
  const base = fixture(0), leaf = base.children.find(child => child.endsWith('/original_go_raw'));
  for (const action of ['fail', 'skip']) {
    const events = base.events.map(event => event.Test === leaf && event.Action === 'pass' ? {...event, Action: action} : event);
    assert.throws(() => auditor.auditOwner(base.inventory, raw(events), 0));
  }
  for (const change of [
    events => events.filter(event => event.Test !== leaf),
    events => events.filter(event => !(event.Test === leaf && event.Action === 'pass')),
    events => [...events.slice(0, -1), {Action: 'pass', Package: 'github.com/xgo-dev/plan9asm', Test: leaf}, events.at(-1)],
    events => events.map(event => event.Test === leaf ? {...event, Test: leaf + '/foreign'} : event),
    events => events.slice(0, -1),
    events => [{Action: 'output', Package: 'github.com/xgo-dev/plan9asm', Output: 'all reductions passed\n'}, events.at(-1)],
  ]) assert.throws(() => auditor.auditOwner(base.inventory, raw(change(base.events)), 0));
  assert.throws(() => auditor.auditOwner(base.inventory, raw(base.events), 1));
  assert.throws(() => auditor.auditOwner(base.inventory + 'TestForeign\n', raw(base.events), 0));
});

test('all12 actual opcodes and enabled native state must precede every runtime child', () => {
  const base = fixture(1);
  for (const [before, after] of [
    ['SSE3=1', 'SSE3=0'], ['SSE41=1', 'SSE41=0'], ['AVX=1', 'AVX=0'],
    ['OSXSAVE=1', 'OSXSAVE=0'], ['XCR0=7', 'XCR0=3'],
    ['members=fff', 'members=7ff'], ['PACKED_REDUCTION_NATIVE_SSE3_SSE41_AVX_OK', 'not_executed'],
  ]) {
    const events = base.events.map(event => event.Output ? {...event, Output: event.Output.replace(before, after)} : event);
    assert.throws(() => auditor.auditOwner(base.inventory, raw(events), 1), before);
  }
  const late = base.events.filter(event => !event.Output);
  late.splice(late.length - 2, 0, ...base.events.filter(event => event.Output));
  assert.throws(() => auditor.auditOwner(base.inventory, raw(late), 1));
});

test('complete reduction audit reopens all four current-head raw streams', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reduction-native-audit-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const head = 'a'.repeat(40), directories = [];
  for (let owner = 0; owner < 4; owner++) {
    const data = fixture(owner), child = path.join(directory, String(owner));
    fs.mkdirSync(child);
    fs.writeFileSync(path.join(child, 'context.json'), JSON.stringify({schema: 1, head, owner}));
    fs.writeFileSync(path.join(child, 'inventory.log'), data.inventory);
    fs.writeFileSync(path.join(child, 'raw.jsonl'), raw(data.events));
    directories.push(child);
  }
  assert.deepEqual(auditor.auditComplete(directories, head), {
    head, owners: 4, roots: 8, children: 285, passed: 293,
    valueKernels: 258, faultKernels: 37, skipped: 0, incomplete: 0,
  });
  assert.throws(() => auditor.auditComplete(directories.slice(0, -1), head));
  assert.throws(() => auditor.auditComplete([...directories.slice(0, -1), directories[0]], head));
  assert.throws(() => auditor.auditComplete(directories, 'b'.repeat(40)));
  fs.writeFileSync(path.join(directories[3], 'raw.jsonl'), '{"allPassed":true}\n');
  assert.throws(() => auditor.auditComplete(directories, head));
});
