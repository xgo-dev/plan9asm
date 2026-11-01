'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const {test} = require('node:test');

const read = file => fs.readFileSync(file, 'utf8');
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const matrix = read('amd64_fixed_local_data_matrix_go127_test.go');
const objects = read('amd64_fixed_local_data_go127_test.go');
const runtime = read('amd64_fixed_local_data_runtime_go127_test.go');
const frame = read('amd64_fixed_local_frame_test.go');
const fresh = frame.slice(frame.indexOf('func fixedLocalFreshAPIs('), frame.indexOf('\nfunc fixedLocalAPI('));
const single = frame.slice(frame.indexOf('func fixedLocalAPI('), frame.indexOf('\nfunc fixedLocalRequireContext('));

function requireFreshOwner(source) {
  assert.match(source, /fixedLocalFreshAPIs\(t, pkg, request, options, \[\]string\{"Translate", "Module", "GoModule"\}/);
  assert.doesNotMatch(source, /requireGoAMD64FrameCapture\(|runtimeOracleStageContext\(|source\.BindFixedLocal\(|fixedLocalDataAPIs\(/);
}

function originalCacheSetup(source, owners) {
  // Cache policy checks owner selection and preparation order; Go lifecycle
  // tests exercise the process-owned cache and independent source workspaces.
  // Normalize only this setup call, keeping the original numerical and
  // mutation/Close fingerprints unchanged.
  const prepared = '\tgoAMD64FramePrepareOwnedToolCache(t)\n';
  assert.equal(source.split(prepared).length - 1, owners);
  return source.replaceAll(prepared, '\tt.Setenv("GOCACHE", t.TempDir())\n');
}

test('every complete readonly DATA consumer owns a fresh lease per API', () => {
  requireFreshOwner(matrix.slice(matrix.indexOf('func fixedLocalDataTargetConsumers('), matrix.indexOf('\nfunc TestGoAMD64FixedLocalReadonlyDataRejectsUnownedAccesses(')));
  requireFreshOwner(objects.slice(objects.indexOf('func TestGoAMD64FixedLocalReadonlyDataThreeTargetObjects('), objects.indexOf('\nfunc fixedLocalDataAPIs(')));
  requireFreshOwner(runtime);
});

test('the shared fresh owner passes complete preprocessed DATA to the single API implementation', () => {
  assert.match(fresh, /fixedLocalAPI\(t, pkg, file, bound, api, check, expanded\)/);
  assert.match(single, /assembly \.\.\.string/);
  assert.match(single, /len\(assembly\) > 1/);
  assert.match(single, /len\(assembly\) == 1 && assembly\[0\] == ""/);
  assert.match(single, /if len\(assembly\) == 1 \{\s*source\.WriteString\(assembly\[0\]\)/);
  assert.match(single, /TranslateGoModule\(pkg, \[\]byte\(source\.String\(\)\)/);
  assert.match(fresh, /defer cancel\(\)/);
  assert.match(fresh, /defer func\(\) \{\s*if err := source\.Close\(\)/);
  assert.match(single, /defer ctx\.Dispose\(\)/);
  assert.match(single, /defer module\.Dispose\(\)/);
  assert.match(single, /defer translation\.Module\.Dispose\(\)/);
});

test('the complete literal matrix retains all original 119 operations and four source batches on every target', () => {
  const builder = matrix.slice(matrix.indexOf('func fixedLocalDataOperations('), matrix.indexOf('\nfunc TestGoAMD64FixedLocalReadonlyDataLinuxRegisteredConsumers('));
  assert.equal(sha(builder), 'e34a575231dceb014395766eba83308b6a8e078a57082b90ccc6ed92b5b3d3d9');
  for (const [target, triple] of [['linux/amd64', 'x86_64-unknown-linux-gnu'], ['darwin/amd64', 'x86_64-apple-darwin'], ['windows/amd64', 'x86_64-pc-windows-msvc']]) {
    assert.ok(matrix.includes(`fixedLocalDataTargetConsumers(t, "${target}", "${triple}")`));
  }
  assert.match(matrix, /len\(operations\) != 119/);
  assert.match(matrix, /for start := 0; start < len\(operations\); start \+= 32/);
  assert.match(matrix, /for index := start; index < end; index\+\+/);
  assert.match(matrix, /assembly\.WriteString\(strings\.Replace\(fixedLocalLiteralData, "\$32", "\$64", 1\)\)/);
  assert.match(matrix, /compileLLVMToObject\(t, llc, triple, "literal-consumers\.ll"/);
  assert.match(matrix, /compileLLVMToObject\(t, llc, triple, "literal-consumers-opt\.ll"/);
});

test('original runtime values are unchanged outside independent tool preparation', () => {
  const original = originalCacheSetup(runtime.slice(0, runtime.indexOf('\tpkg, request,')), 1);
  assert.equal(sha(original), '85e040739a6a7623e4ef1797241e4ee9ab93bca60203975369762e6e68b16eda');
  assert.match(runtime, /fixedLocalPackedRunOriginal\(t, execution, assembly\.String\(\), declarations\.String\(\), goOracle, true\)/);
  assert.match(runtime, /\[\]string\{"-O0", "-O2"\}/);
});

test('negative shared-binding mutation/Close controls are not renewed', () => {
  const guards = read('amd64_fixed_local_data_guards_go127_test.go');
  const additional = guards.indexOf('\nfunc TestGoAMD64FixedLocalReadonlyDataCLIEmissionIdentity(');
  assert.ok(additional > 0, 'the independent emission-identity regression must remain present');
  // Appending another independent owner must not change the original controls'
  // fingerprint or require pretending it shares their cache/observation.
  const original = originalCacheSetup(guards.slice(0, additional), 2);
  assert.equal(sha(original), '3730f8eaf2f8485989658c94056002b6508f8cae74a14ba56c7c6c956f472d1a');
  originalCacheSetup(guards.slice(additional), 1);
});
