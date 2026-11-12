'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const {auditNativeOwners} = require('./audit-native-owners.cjs');

const owners = 8;
const pipelines = ['backend_O0', 'backend_O2', 'IR_O2_backend_O2'];
const statusRoot = 'TestCrossLinuxRuntimeMatrixX86PackedConversionNativeAVX512Status';
const faultRoot = 'TestCrossLinuxRuntimeMatrixX86PackedConversionNativeDeadFaults';
const independentRoot = 'TestCrossLinuxRuntimeMatrixX86PackedConversionNativeIndependentC';

function partition(root, owner) {
  assert.ok(Number.isInteger(owner) && owner >= 0 && owner < owners, 'invalid native conversion owner');
  return root + (owner ? 'Part' + owner : '');
}

function batches(count, limit, owner) {
  const selected = [];
  for (let start = 0, batch = 0; start < count; start += limit, batch++) {
    if (batch % owners === owner) selected.push([start, Math.min(start + limit, count)]);
  }
  assert.ok(selected.length > 0, 'empty native conversion partition');
  return selected;
}

function required(owner) {
  const roots = [partition(statusRoot, owner), partition(faultRoot, owner)];
  if (!owner) roots.push(independentRoot);
  const children = [];
  const values = batches(692, 64, owner);
  const faults = batches(222, 16, owner);
  for (const [root, selected, originals] of [
    [roots[0], values, ['original_go_named', 'original_go_raw']],
    [roots[1], faults, ['original_go_opcode_reference']],
  ]) {
    for (const [start] of selected) {
      const batch = root + '/batch-' + String(start).padStart(4, '0');
      children.push(batch, ...originals.map(original => batch + '/' + original));
      for (const spelling of ['named', 'raw']) {
        const source = batch + '/' + spelling;
        children.push(source);
        for (const api of ['text', 'module', 'Go']) {
          const publicPath = source + '/' + api;
          children.push(publicPath, ...pipelines.map(pipeline => publicPath + '/' + pipeline));
        }
      }
    }
  }
  if (!owner) children.push(...pipelines.map(pipeline => independentRoot + '/' + pipeline));
  return {roots, children, values, faults};
}

function auditOwner(inventory, raw, owner) {
  const expected = required(owner);
  const result = auditNativeOwners(inventory, raw, expected.roots, expected.children);
  const output = new Map(expected.roots.map(root => [root, '']));
  const preflights = new Set();
  for (const line of raw.split(/\r?\n/).filter(Boolean)) {
    const event = JSON.parse(line);
    if (event.Action === 'output' && output.has(event.Test)) {
      assert.equal(typeof event.Output, 'string', 'invalid native CPU observation');
      output.set(event.Test, output.get(event.Test) + event.Output);
    }
    if (event.Action !== 'run' || !expected.children.includes(event.Test)) continue;
    const root = event.Test.split('/')[0];
    const observation = output.get(root);
    const flags = observation.match(/AVX512F=1 AVX512DQ=1 AVX512BW=1 AVX512VL=1 OSXSAVE=1 XCR0=([0-9a-f]+)\b/);
    assert.ok(flags, 'missing current native F/DQ/BW/VL or OS state: ' + root);
    assert.equal(BigInt('0x' + flags[1]) & 0xe6n, 0xe6n, 'incomplete native XCR0: ' + root);
    assert.ok(observation.includes('PACKED_CONVERSION_NATIVE_F_DQ_BW_VL_OK'),
      'original native conversion opcodes did not complete before runtime: ' + root);
    preflights.add(root);
  }
  assert.equal(preflights.size, expected.roots.length, 'missing actual native conversion preflight');
  return {...result, owner, values: expected.values, faults: expected.faults, preflights: preflights.size};
}

function readOwner(directory, owner, head) {
  const context = JSON.parse(fs.readFileSync(path.join(directory, 'context.json'), 'utf8'));
  assert.deepEqual(Object.keys(context).sort(), ['head', 'owner', 'schema'], 'unknown native owner context fields');
  assert.equal(context.schema, 1, 'invalid native owner context schema');
  assert.equal(context.owner, owner, 'native receipt borrowed another partition');
  assert.match(head, /^[0-9a-f]{40}$/, 'invalid current source identity');
  assert.equal(context.head, head, 'native receipt is not the current checked-out source');
  return {...auditOwner(fs.readFileSync(path.join(directory, 'inventory.log'), 'utf8'),
    fs.readFileSync(path.join(directory, 'raw.jsonl'), 'utf8'), owner), head};
}

function auditComplete(directories, head) {
  assert.equal(directories.length, owners, 'missing complete native owner artifacts');
  const seen = new Set(), receipts = [];
  for (const directory of directories) {
    const context = JSON.parse(fs.readFileSync(path.join(directory, 'context.json'), 'utf8'));
    assert.ok(Number.isInteger(context.owner) && context.owner >= 0 && context.owner < owners,
      'invalid complete native partition');
    assert.ok(!seen.has(context.owner), 'duplicated native partition artifact');
    seen.add(context.owner);
    // Reaudit the complete raw stream and fresh inventory, not a printed
    // success string, cached aggregate or self-declared receipt counts.
    receipts.push(readOwner(directory, context.owner, head));
  }
  assert.deepEqual([...seen].sort(), [0, 1, 2, 3, 4, 5, 6, 7], 'incomplete native owner union');
  for (const [field, count] of [['values', 692], ['faults', 222]]) {
    const consumed = new Array(count).fill(0);
    for (const receipt of receipts) {
      for (const [start, end] of receipt[field]) {
        for (let index = start; index < end; index++) consumed[index]++;
      }
    }
    assert.ok(consumed.every(count => count === 1), 'native partitions overlap or omit ' + field);
  }
  return {head, owners, roots: receipts.reduce((sum, receipt) => sum + receipt.roots, 0),
    children: receipts.reduce((sum, receipt) => sum + receipt.children, 0),
    passed: receipts.reduce((sum, receipt) => sum + receipt.passed, 0),
    valueKernels: 692, faultKernels: 222, skipped: 0, incomplete: 0};
}

function artifactDirectories(root) {
  const found = [];
  for (const entry of fs.readdirSync(root, {withFileTypes: true})) {
    assert.ok(!entry.isSymbolicLink(), 'native artifacts cannot redirect source receipts');
    if (!entry.isDirectory()) continue;
    const directory = path.join(root, entry.name);
    assert.ok(fs.existsSync(path.join(directory, 'context.json')), 'unrecognized native owner artifact');
    found.push(directory);
  }
  return found;
}

module.exports = {required, auditOwner, readOwner, auditComplete};

if (require.main === module) {
  const [command, argument, directory] = process.argv.slice(2);
  if (command === 'roots') {
    process.stdout.write(required(Number(argument)).roots.join('|') + '\n');
  } else {
    const head = execFileSync('git', ['rev-parse', 'HEAD'], {encoding: 'utf8'}).trim();
    const result = command === 'owner' ? readOwner(directory, Number(argument), head) :
      command === 'complete' ? auditComplete(artifactDirectories(argument), head) : null;
    assert.ok(result, 'unknown native conversion audit command');
    process.stdout.write(JSON.stringify(result) + '\n');
  }
}
