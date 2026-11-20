const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');
const { auditARM64Fallback } = require('./audit-arm64-fallback.cjs');

const root = 'TestFallbackARM64WideFrameCompilesWithLLVM22';
const pkg = 'github.com/xgo-dev/plan9asm/cmd/plan9asmll';
const names = [root, ...['darwin', 'linux', 'windows', 'native_complete-argument_oracle']
  .map(child => `${root}/${child}`)];
const events = [
  ...names.map(Test => ({ Action: 'run', Test, Package: pkg })),
  ...names.slice().reverse().map(Test => ({ Action: 'pass', Test, Package: pkg })),
  { Action: 'pass', Package: pkg },
];
const raw = value => value.map(event => JSON.stringify(event)).join('\n') + '\n';

test('mandatory ARM64 runtime axes supplement the exhaustive runner audit', () => {
  assert.deepEqual(auditARM64Fallback(raw(events)), {
    roots: 1, children: 4, passed: 5, skipped: 0, incomplete: 0,
  });
});

test('successful Go dependency build output is not a failed runtime axis', () => {
  const dependency = { Action: 'build-output', ImportPath: 'example.invalid/dependency', Output: 'compiler diagnostic\n' };
  assert.equal(auditARM64Fallback(raw([dependency, ...events])).children, 4);
});

test('the selected cross scope binds the actual Node auditor through the shared observer', () => {
  const source = fs.readFileSync('cmd/plan9asmtest/ci_scope.go', 'utf8');
  assert.match(source, /if os\.Getenv\("PLAN9ASM_CROSS_EXEC"\) == "1" && !cfg\.Module \{\s*if err := captureCINodeDependency\(ctx, cfg, stem, origins\); err != nil/);
});

test('missing, skipped, duplicated or incomplete execution cannot count as covered', () => {
  const native = names[4];
  const mutations = [
    events.filter(event => event.Test !== native),
    events.filter(event => !(event.Test === native && event.Action === 'pass')),
    events.filter(event => event.Test),
    events.map(event => event.Test === native && event.Action === 'pass' ? { ...event, Action: 'skip' } : event),
    events.map(event => !event.Test ? { ...event, Action: 'fail' } : event),
    events.map(event => ({ ...event, Package: pkg + '/foreign' })),
    [events[0], ...events],
    [...events.slice(0, -1), events[8], events.at(-1)],
    [...events, events[0]],
    [{ Action: 'build-output', ImportPath: '', Output: 'unidentified' }, ...events],
    [{ Action: 'build-output', ImportPath: 'dep', Test: root }, ...events],
    [{ Action: 'build-fail', ImportPath: 'dep' }, ...events],
  ];
  for (const mutation of mutations) {
    assert.throws(() => auditARM64Fallback(raw(mutation)));
  }
  assert.throws(() => auditARM64Fallback('{not JSON}\n'));
  assert.throws(() => auditARM64Fallback(''));
});

function requireDriver(source) {
  assert.match(source, /PLAN9ASM_CROSS_EXEC:-\} != 1/);
  assert.match(source, /root=TestFallbackARM64WideFrameCompilesWithLLVM22\n/);
  assert.match(source, /go run \.\/cmd\/plan9asmtest -dir cmd\/plan9asmll -out/);
  assert.match(source, /-ci-selector "\^\$\{root\}\$" -ci-isolate-root "\$root"/);
  assert.match(source, /-shards 2 -timeout 5m/);
  assert.match(source, /for owner in 0 1; do/);
  assert.match(source, /-verify-ci-partitions "\$base\/owners"/);
  assert.match(source, /node \.github\/scripts\/audit-arm64-fallback\.cjs/);
  assert.match(source, /cross-runtime-owner-0\/root-0000\.stdout/);
  assert.doesNotMatch(source, /continue-on-error|\|\| true|-run[= ]|timeout (?:10|20|30)m/);
}

test('ARM64 driver keeps actual nested-module discovery and strict fresh verification', () => {
  const source = fs.readFileSync('scripts/test-arm64-fallback-ci.sh', 'utf8');
  requireDriver(source);
  for (const [before, after] of [
    ['-dir cmd/plan9asmll', '-dir .'],
    ['^${root}$', '${root}'],
    ['for owner in 0 1;', 'for owner in 0;'],
    ['-verify-ci-partitions', '-verify-removed'],
    ['audit-arm64-fallback.cjs', 'audit-removed.cjs'],
    ['PLAN9ASM_CROSS_EXEC:-} != 1', 'PLAN9ASM_CROSS_EXEC:-} != 0'],
    ['-timeout 5m', '-timeout 20m'],
  ]) {
    const changed = source.replace(before, after);
    assert.notEqual(changed, source);
    assert.throws(() => requireDriver(changed));
  }
});
