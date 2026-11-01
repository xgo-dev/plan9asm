'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');

test('Windows execution and completion share the explicit optional AVX512 policy', () => {
  const workflow = fs.readFileSync('.github/workflows/windows-module.yml', 'utf8');
  assert.match(workflow, /^env:\n  PLAN9ASM_AVX512_RUNTIME: auto\n/m);
  assert.equal((workflow.match(/PLAN9ASM_AVX512_RUNTIME/g) || []).length, 1,
    'individual owners cannot override the common execution environment');
});
