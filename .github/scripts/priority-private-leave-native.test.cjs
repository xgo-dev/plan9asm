'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');

const root = 'TestCrossLinuxRuntimeMatrixX86LeavePrivateEmitterWidthsAndFlags';
const architectures = ['amd64', '386'];
const paths = ['backend_O0', 'backend_O2', 'IR_O2/backend_O2'];
const groups = architectures.map(arch => root + '/' + arch);
const leaves = groups.flatMap(group => paths.map(path => group + '/' + path));
const names = [root, ...groups, ...leaves];
const hash = 'a'.repeat(64);
const host = `IA32 direct host: linux/amd64 kernel=x86_64 CPUsha=${hash} mapsha=${hash}\n`;
const sdk = arch => `actual LEA source/object receipt: SDK=go1.27.2 target=linux/${arch} source=${hash} driver=${hash} object=${hash}\n`;
const marker = arch => `private LEAVE numerical completion arch=${arch}: PRIVATE_LEAVE_128_WIDTH_VALUES_FLAGS_CANARIES_PASS\n`;
const image = `native oracle static IA32 ELF bytes=512 sha256=${hash}\n`;
const command = `actual executable=/tmp/private-leave sha256=${hash} argv=[]\n`;
const direct = `IA32 direct ELF bytes=512 sha256=${hash} argv=[]\n`;
const event = (Action, Test, Output) => ({Action, Package: 'github.com/xgo-dev/plan9asm',
  ...(Test ? {Test} : {}), ...(Output !== undefined ? {Output} : {})});

function completeEvents() {
  const events = [event('start'), event('run', root), event('output', root, host)];
  for (const arch of architectures) {
    const group = root + '/' + arch;
    events.push(event('run', group), event('output', group, sdk(arch)));
    for (const path of paths) {
      const leaf = group + '/' + path;
      events.push(event('run', leaf), event('output', leaf,
        (arch === '386' ? image + command + direct : '') + marker(arch)), event('pass', leaf));
    }
    events.push(event('pass', group));
  }
  events.push(event('output', root, host), event('pass', root), event('pass'));
  return events;
}

function audit(events = completeEvents(), inventory = root + '\n') {
  assert.ok(fs.existsSync('.github/scripts/audit-private-leave-native.cjs'), 'private LEAVE lacks its exact native-width auditor');
  return require('./audit-private-leave-native.cjs').auditPrivateLEAVE(inventory,
    events.map(value => JSON.stringify(value)).join('\n'));
}

test('private LEAVE requires all four width values with six actual pipelines, not a native Go ABI claim', () => {
  assert.deepEqual(audit(), {roots: 1, children: 8, passed: 9, skipped: 0, incomplete: 0,
    nativeHosts: 2, sdkCaptures: 2, llvmExecutions: 6, staticIA32Executions: 3, privateNumericalOnly: true});
});

test('private LEAVE rejects missing duplicate failed skipped incomplete and late lifecycle evidence', () => {
  audit();
  for (const name of names) {
    for (const Action of ['fail', 'skip']) assert.throws(() => audit(completeEvents().map(value =>
      value.Test === name && value.Action === 'pass' ? {...value, Action} : value)), name + Action);
    for (const Action of ['run', 'pass']) {
      const events = completeEvents();
      const at = events.findIndex(value => value.Test === name && value.Action === Action);
      assert.throws(() => audit(events.filter((_, index) => index !== at)), name + ' missing ' + Action);
      events.splice(at, 0, events[at]);
      assert.throws(() => audit(events), name + ' duplicate ' + Action);
    }
    const events = completeEvents();
    const at = events.findIndex(value => value.Test === name && value.Action === 'pass');
    events.splice(at + 1, 0, event('output', name, 'late completion\n'));
    assert.throws(() => audit(events), name + ' output outside running owner');
  }
  for (const inventory of ['', root + '\n' + root + '\n', 'TestUnrelated\n']) assert.throws(() => audit(completeEvents(), inventory));
  for (const events of [completeEvents().slice(1), completeEvents().slice(0, -1),
    [event('output', undefined, 'all widths passed')], [event('start'), ...completeEvents()],
    [...completeEvents(), event('pass')], completeEvents().map(value => ({...value, Package: 'foreign'}))]) {
    assert.throws(() => audit(events));
  }
});

test('private LEAVE binds actual host SDK static ELF hash and every complete execution to its own live owner', () => {
  audit();
  for (const needle of [host, ...architectures.map(sdk), image, command, direct, ...architectures.map(marker)]) {
    for (const replacement of ['', needle + needle, needle.replace(hash, 'invalid'),
      needle.replace('128', '127').replace('linux/amd64', 'linux/arm64').replace('arch=386', 'arch=amd64')]) {
      if (replacement === needle) continue;
      assert.throws(() => audit(completeEvents().map(value => value.Output
        ? {...value, Output: value.Output.replace(needle, replacement)} : value)), needle);
    }
  }
  for (const needle of [image, command, direct]) {
    assert.throws(() => audit(completeEvents().map(value => value.Output
      ? {...value, Output: value.Output.replace(needle, needle.replace(hash, 'b'.repeat(64)))} : value)));
  }
  const lateSDK = completeEvents();
  const capture = lateSDK.splice(lateSDK.findIndex(value => value.Output === sdk('amd64')), 1)[0];
  lateSDK.splice(lateSDK.findIndex(value => value.Test === root + '/amd64/backend_O0' && value.Action === 'pass'), 0, capture);
  assert.throws(() => audit(lateSDK), 'SDK must precede actual compilation/execution');
  const earlyHost = completeEvents();
  const post = earlyHost.splice(earlyHost.length - 3, 1)[0];
  earlyHost.splice(4, 0, post);
  assert.throws(() => audit(earlyHost), 'final host must follow both complete architectures');
  const borrowed = completeEvents().map(value => value.Test === root + '/386/backend_O0' && value.Output
    ? {...value, Test: root + '/386'} : value);
  assert.throws(() => audit(borrowed), 'a parent cannot replace a leaf execution');
});
