'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');

const root = 'TestCrossLinuxRuntimeMatrixX86LEAWRetainedPointerOriginalBytesAndNativeDF';
const apis = ['text', 'module', 'Go'];
const paths = ['backend_O0', 'backend_O2', 'IR_O2/backend_O2'];
const children = [...apis.flatMap(api => [root + '/' + api,
  ...paths.map(path => root + '/' + api + '/' + path)]), root + '/OriginalGoBytes'];
const inventory = root + '\nok\tgithub.com/xgo-dev/plan9asm\n';
const hash = 'a'.repeat(64);
const host = `IA32 direct host: linux/amd64 kernel=x86_64 CPUsha=${hash} mapsha=${hash}\n`;
const sdk = `actual LEA source/object receipt: SDK=go1.27.2 target=linux/amd64 source=${hash} driver=${hash} object=${hash}\n`;
const completion = 'LEAW_RETAINED_POINTER_300_VALUES_STATUS_CANARIES_PASS\n';
const llvm = 'native retained LEAW LLVM execution: ' + completion;
const original = 'native retained LEAW actual Go bytes execution: ' + completion;
const event = (Action, Test, Output) => ({Action, Package: 'github.com/xgo-dev/plan9asm',
  ...(Test ? {Test} : {}), ...(Output !== undefined ? {Output} : {})});
const serialize = events => events.map(value => JSON.stringify(value)).join('\n');

function completeEvents() {
  const events = [event('start'), event('run', root), event('output', root, host + sdk)];
  for (const api of apis) {
    const group = root + '/' + api;
    events.push(event('run', group));
    for (const path of paths) {
      const leaf = group + '/' + path;
      events.push(event('run', leaf), event('output', leaf, llvm), event('pass', leaf));
    }
    events.push(event('pass', group));
  }
  events.push(event('run', root + '/OriginalGoBytes'), event('output', root + '/OriginalGoBytes', original),
    event('pass', root + '/OriginalGoBytes'), event('output', root, host), event('pass', root), event('pass'));
  return events;
}

function audit(events = completeEvents(), discovered = inventory) {
  assert.ok(fs.existsSync('.github/scripts/audit-native-leaw.cjs'), 'LEAW lacks a required exact native completion auditor');
  return require('./audit-native-leaw.cjs').auditNativeLEAW(discovered, serialize(events));
}

test('native LEAW requires its unique root, three API parents, nine LLVM leaves and actual Go bytes', () => {
  assert.deepEqual(audit(), {roots: 1, children: 13, passed: 14, skipped: 0, incomplete: 0,
    nativeHosts: 2, sdkCaptures: 1, llvmExecutions: 9, originalByteExecutions: 1});
});

test('native LEAW rejects missing duplicated failed skipped and incomplete lifecycle terminals', () => {
  audit();
  for (const name of [root, ...children]) {
    for (const Action of ['fail', 'skip']) {
      assert.throws(() => audit(completeEvents().map(value => value.Test === name && value.Action === 'pass'
        ? {...value, Action} : value)), name + Action);
    }
    for (const Action of ['run', 'pass']) {
      const events = completeEvents();
      const at = events.findIndex(value => value.Test === name && value.Action === Action);
      assert.throws(() => audit(events.filter((_, index) => index !== at)), name + ' missing ' + Action);
      events.splice(at, 0, events[at]);
      assert.throws(() => audit(events), name + ' duplicate ' + Action);
    }
    const late = completeEvents();
    const at = late.findIndex(value => value.Test === name && value.Action === 'pass');
    late.splice(at + 1, 0, event('output', name, 'late output after the terminal\n'));
    assert.throws(() => audit(late), name + ' output after pass');
  }
  for (const discovered of ['', inventory + root + '\n', inventory.replace(root, 'TestUnrelated')]) {
    assert.throws(() => audit(completeEvents(), discovered));
  }
  for (const events of [completeEvents().slice(1), completeEvents().slice(0, -1),
    [...completeEvents(), event('pass')], [event('start'), ...completeEvents()],
    [event('output', undefined, '14 passed')],
    completeEvents().map(value => ({...value, Package: 'foreign/package'}))]) assert.throws(() => audit(events));
});

test('native LEAW binds real host brackets SDK capture and each actual execution marker to its own live owner', () => {
  audit();
  for (const needle of [host, sdk]) {
    for (const replacement of ['', needle + needle, needle.replace('linux/amd64', 'linux/arm64'),
      needle.replace(hash, 'invalid')]) {
      assert.throws(() => audit(completeEvents().map(value => value.Test === root && value.Output
        ? {...value, Output: value.Output.replace(needle, replacement)} : value)), needle);
    }
  }
  for (const name of children.filter(name => !apis.some(api => name === root + '/' + api))) {
    const marker = name.endsWith('/OriginalGoBytes') ? original : llvm;
    for (const replacement of ['', marker + marker, marker.replace('300', '299'),
      marker === original ? llvm : original, sdk + marker, host + marker]) {
      assert.throws(() => audit(completeEvents().map(value => value.Test === name && value.Output
        ? {...value, Output: value.Output.replace(marker, replacement)} : value)), name);
    }
  }
  const early = completeEvents();
  const originalEvents = early.filter(value => value.Test === root + '/OriginalGoBytes');
  const others = early.filter(value => value.Test !== root + '/OriginalGoBytes');
  others.splice(3, 0, ...originalEvents);
  assert.throws(() => audit(others), 'original bytes cannot precede complete API groups');
  const misplaced = completeEvents().map(value => value.Test === root + '/text/backend_O0' && value.Output
    ? {...value, Test: root + '/text'} : value);
  assert.throws(() => audit(misplaced), 'an API parent cannot replace an executed leaf');
  const late = completeEvents();
  const at = late.findIndex(value => value.Action === 'output' && value.Test === root);
  late[at] = event('output', root, host);
  late.splice(5, 0, event('output', root, sdk));
  assert.throws(() => audit(late), 'SDK capture must precede the API run');
});
