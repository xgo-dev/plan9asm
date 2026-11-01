const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const {jobBody} = require('./workflow-needs.cjs');

const workflow = fs.readFileSync(path.join(__dirname, '../workflows/go-ci.yml'), 'utf8');

function jobSection(name, source = workflow) {
  return jobBody(source, name);
}

function policySelector(source) {
  const steps = jobSection('ci_policy', source).split(/(?=^      - )/m);
  const selected = steps.filter(step => step.startsWith('      - name: CI policy tests\n'));
  assert.equal(selected.length, 1, 'one actual Go policy execution step required');
  assert.doesNotMatch(selected[0], /^        (?:if|continue-on-error):/m);
  const commands = [...selected[0].matchAll(/^        run: go test \. -run '([^']+)' -count=1$/gm)];
  assert.equal(commands.length, 1, 'one uncached, unmasked root-package policy command required');
  return commands[0][1];
}

function requireCompletePolicy(source) {
  assert.equal(policySelector(source),
    '^(TestCI|TestFixedLocal|TestGoAMD64FixedLocalPackedRuntimeOwnership|TestRuntimeOracleCommand(ConsumersRetainOwnedExecution|AuditDistinguishesTestingRun)$)',
    'preflight must select complete static-contract prefixes, not a manually enumerated subset');
  const policy = jobSection('ci_policy', source);
  assert.match(policy, /^    timeout-minutes: 20$/m);
  assert.match(policy, /^          go-version: '1\.27\.1'$/m);
  assert.match(policy, /^        run: bash scripts\/install-ci-llvm22-ubuntu\.sh$/m);
  assert.match(policy, /^        uses: \.\/\.github\/actions\/setup-node22$/m);
  assert.doesNotMatch(policy, /^    (?:needs|if|continue-on-error):/m);
}

test('translator jobs require policy preflight, not external compatibility', () => {
  for (const name of [
    'fmt', 'build',
    'stdlib-corpus', 'cross-runtime', 'test', 'nested-cli', 'arm-scan', 'race', 'coverage', 'nested-cli-coverage',
  ]) {
    const section = jobSection(name);
    assert.match(section, /^    needs: ci_policy$/m, name);
    // Native needs success gating must not be bypassed by always()/!cancelled().
    assert.doesNotMatch(section, /^    if:/m, name);
  }
  assert.doesNotMatch(workflow, /discovered_library|reported_library|testdata\/discovery/);
});

test('all translator matrix failures remain failures', () => {
  for (const name of ['test', 'nested-cli', 'race', 'coverage', 'nested-cli-coverage', 'cross-runtime']) {
    const job = jobSection(name);
    assert.match(job, /^      fail-fast: false$/m);
    assert.doesNotMatch(job, /continue-on-error:/);
  }
});

test('cheap CI policy checks pass before instruction and official corpus jobs', () => {
  const policy = jobSection('ci_policy');
  assert.match(policy, /bash scripts\/install-ci-llvm22-ubuntu\.sh/);
  assert.match(policy, /node --test \.github\/scripts\/priority-\*\.test\.cjs/);
  requireCompletePolicy(workflow);
  assert.doesNotMatch(policy, /^    (needs|if):/m);
  assert.ok(workflow.indexOf('\n  ci_policy:\n') <
    workflow.indexOf('\n  test:\n'));
});

test('PR preflight selects every existing CI and FixedLocal static contract', () => {
  requireCompletePolicy(workflow);
  const selected = new RegExp(policySelector(workflow));
  const root = path.join(__dirname, '../..');
  const names = fs.readdirSync(root).filter(file => file.endsWith('_test.go')).flatMap(file =>
    [...fs.readFileSync(path.join(root, file), 'utf8').matchAll(
      /^func (Test(?:CI|FixedLocal)[A-Za-z0-9_]+|TestGoAMD64FixedLocalPackedRuntimeOwnership|TestRuntimeOracleCommand(?:ConsumersRetainOwnedExecution|AuditDistinguishesTestingRun))\(t \*testing\.T\)/gm,
    )].map(match => match[1]));
  for (const guard of [
    'TestFixedLocalWideCompileOnlyOwnersDoNotRequireRuntimeTransport',
    'TestFixedLocalCompileOnlyToolsRetainExactLLVMAndSDKWithoutExecution',
    'TestFixedLocalSharedHelpersBuildOnAllHosts',
    'TestGoAMD64FixedLocalPackedRuntimeOwnership',
    'TestRuntimeOracleCommandConsumersRetainOwnedExecution',
    'TestRuntimeOracleCommandAuditDistinguishesTestingRun',
  ]) assert.ok(names.includes(guard), 'independently required source guard missing: ' + guard);
  for (const name of names) assert.ok(selected.test(name), 'preflight omitted existing static contract: ' + name);
});

test('preflight includes future static contracts without selecting expensive execution owners', () => {
  const selected = new RegExp(policySelector(workflow));
  for (const name of ['TestCIFutureSchedulingContract', 'TestFixedLocalFutureSourceOwnershipContract',
    'TestGoAMD64FixedLocalPackedRuntimeOwnership']) {
    assert.ok(selected.test(name), 'new static contracts must not need another suffix allowlist: ' + name);
  }
  for (const name of [
    'TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalPackedNativeWideBatch00',
    'TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalPackedNativeWideBatch05',
    'TestGoAMD64FixedLocalPackedWideRuntimeOracleCompileOnly',
    'TestGoAMD64FixedLocalConversionActualObjectsLinuxBatch00',
    'TestGoAMD64FixedLocalReadonlyDataWindowsRegisteredConsumers',
    'TestX86AESFamilyActualBoundFixedLocalConsumers',
    'TestRuntimeOracleCommandRequiresBoundContextAndOutput',
    'TestRuntimeOracleCommandConsumersRetainOwnedExecutionNative',
    'TestRuntimeOracleCommandAuditDistinguishesTestingRunNative',
  ]) assert.ok(!selected.test(name), 'cheap preflight acquired an actual native/object owner: ' + name);
});

test('preflight rejects stale suffix allowlists, missing contract families and failure masking', () => {
  requireCompletePolicy(workflow);
  const command = "run: go test . -run '" + policySelector(workflow) + "' -count=1";
  for (const selector of [
    '^TestCI',
    '^(TestCI|TestFixedLocal(APIsHaveIndependentBoundedCaptureLeases|WideCompileOnlyHasThreeCompleteAPIOwners)|TestGoAMD64FixedLocalPackedRuntimeOwnership)',
    '^(TestFixedLocal|TestGoAMD64FixedLocalPackedRuntimeOwnership)',
    '^(TestCI|TestFixedLocal)',
    '^(TestCI|TestFixedLocal|TestGoAMD64FixedLocalPackedRuntimeOwnership)',
    '^Test',
  ]) assert.throws(() => requireCompletePolicy(workflow.replace(command,
    () => "run: go test . -run '" + selector + "' -count=1")));
  for (const changed of ['run: echo policy', command + ' || true',
    "if: false\n        " + command]) {
    assert.throws(() => requireCompletePolicy(workflow.replace(command, () => changed)));
  }
});
