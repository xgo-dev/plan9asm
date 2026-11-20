'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const {auditNativeOwners} = require('./audit-native-owners.cjs');

const owners = 4;
const pipelines = ['backend_O0', 'backend_O2', 'IR_O2_backend_O2'];

function batches(count, limit, owner) {
  assert.ok(Number.isInteger(owner) && owner >= 0 && owner < owners, 'invalid native reduction owner');
  const selected = [];
  for (let start = 0, batch = 0; start < count; start += limit, batch++) {
    if (batch % owners === owner) selected.push([start, Math.min(start + limit, count)]);
  }
  assert.ok(selected.length > 0, 'empty native reduction partition');
  return selected;
}

function required(owner) {
  const values = batches(258, 64, owner), faults = batches(37, 8, owner);
  const roots = ['Values', 'DeadFaults'].map(family =>
    'TestCrossLinuxRuntimeMatrixX86PackedReductionNative' + family + 'Part' + owner);
  const children = [];
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
      assert.equal(typeof event.Output, 'string', 'invalid native reduction CPU observation');
      output.set(event.Test, output.get(event.Test) + event.Output);
    }
    if (event.Action !== 'run' || !expected.children.includes(event.Test)) continue;
    const root = event.Test.split('/')[0], observation = output.get(root);
    const flags = observation.match(/SSE3=1 SSE41=1 AVX=1 OSXSAVE=1 XCR0=([0-9a-f]+)\b/);
    assert.ok(flags, 'missing current native SSE3/SSE4.1/AVX or OS state: ' + root);
    assert.equal(BigInt('0x' + flags[1]) & 6n, 6n, 'incomplete native XCR0: ' + root);
    assert.ok(observation.includes('PACKED_REDUCTION_NATIVE_SSE3_SSE41_AVX_OK members=fff'),
      'all12 original native reduction opcodes did not complete before runtime: ' + root);
    preflights.add(root);
  }
  assert.equal(preflights.size, expected.roots.length, 'missing actual native reduction preflight');
  return {...result, owner, values: expected.values, faults: expected.faults, preflights: preflights.size};
}

function readOwner(directory, owner, head) {
  const context = JSON.parse(fs.readFileSync(path.join(directory, 'context.json'), 'utf8'));
  assert.deepEqual(Object.keys(context).sort(), ['head', 'owner', 'schema'], 'unknown native context fields');
  assert.equal(context.schema, 1, 'invalid native context schema');
  assert.equal(context.owner, owner, 'native reduction receipt borrowed another partition');
  assert.match(head, /^[0-9a-f]{40}$/, 'invalid current source identity');
  assert.equal(context.head, head, 'native reduction receipt is not the current checked-out source');
  return {...auditOwner(fs.readFileSync(path.join(directory, 'inventory.log'), 'utf8'),
    fs.readFileSync(path.join(directory, 'raw.jsonl'), 'utf8'), owner), head};
}

function auditComplete(directories, head) {
  assert.equal(directories.length, owners, 'missing complete native reduction artifacts');
  const seen = new Set(), receipts = [];
  for (const directory of directories) {
    const context = JSON.parse(fs.readFileSync(path.join(directory, 'context.json'), 'utf8'));
    assert.ok(Number.isInteger(context.owner) && context.owner >= 0 && context.owner < owners,
      'invalid complete native reduction partition');
    assert.ok(!seen.has(context.owner), 'duplicate native reduction artifact');
    seen.add(context.owner);
    receipts.push(readOwner(directory, context.owner, head));
  }
  assert.deepEqual([...seen].sort(), [0, 1, 2, 3], 'incomplete native reduction union');
  for (const [field, count] of [['values', 258], ['faults', 37]]) {
    const consumed = new Array(count).fill(0);
    for (const receipt of receipts) {
      for (const [start, end] of receipt[field]) {
        for (let index = start; index < end; index++) consumed[index]++;
      }
    }
    assert.ok(consumed.every(count => count === 1), 'native reduction partitions overlap or omit ' + field);
  }
  return {head, owners, roots: receipts.reduce((sum, receipt) => sum + receipt.roots, 0),
    children: receipts.reduce((sum, receipt) => sum + receipt.children, 0),
    passed: receipts.reduce((sum, receipt) => sum + receipt.passed, 0),
    valueKernels: 258, faultKernels: 37, skipped: 0, incomplete: 0};
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
    assert.ok(result, 'unknown native reduction audit command');
    process.stdout.write(JSON.stringify(result) + '\n');
  }
}
