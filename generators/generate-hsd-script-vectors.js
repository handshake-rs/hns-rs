#!/usr/bin/env node
'use strict';

const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const HSD_REVISION = '698e252ebc7b5c1dd0a9587e342fdd153d020ae4';
const SCRIPT_TESTS_SHA256 =
  '71548a587d1c7921cb899de192f59ed1833c85a6cd62d9dac8cd5b86b1225c86';
const SCRIPT_IMPLEMENTATION_SHA256 =
  '16faf964ded72d460979e1331c612d9c0555baa5e6731eb33dba21bec896787d';

const hsdRoot = path.resolve(
  process.argv[2] || process.env.HSD_ROOT || '../hsd'
);
const output = path.resolve(
  process.argv[3]
    || path.join(__dirname, '..', 'fixtures', 'hsd', 'script-tests-v1.txt')
);

const testsPath = path.join(hsdRoot, 'test', 'data', 'script-tests.json');
const testsBytes = fs.readFileSync(testsPath);
const testsHash = crypto.createHash('sha256').update(testsBytes).digest('hex');
assert.strictEqual(testsHash, SCRIPT_TESTS_SHA256, 'unexpected script corpus');
const scriptPath = path.join(hsdRoot, 'lib', 'script', 'script.js');
const scriptHash = crypto
  .createHash('sha256')
  .update(fs.readFileSync(scriptPath))
  .digest('hex');
assert.strictEqual(
  scriptHash,
  SCRIPT_IMPLEMENTATION_SHA256,
  'unexpected script implementation'
);

process.env.NODE_BACKEND = 'js';
const Script = require(path.join(hsdRoot, 'lib', 'script', 'script'));
const tests = JSON.parse(testsBytes);
const lines = [
  '# hns-rs HSD script differential corpus v1',
  `# hsd_revision=${HSD_REVISION}`,
  `# source_sha256=${SCRIPT_TESTS_SHA256}`,
  `# cases=${tests.length}`,
  '# index|result|flags|value|locktime|sequence|script_hex|witness_count|witness_hex_csv'
];

for (let index = 0; index < tests.length; index++) {
  const test = tests[index];
  let flags = 0;
  for (const name of test.flags) {
    const flag = Script.flags[`VERIFY_${name}`];
    assert.notStrictEqual(flag, undefined, `unknown flag ${name}`);
    flags |= flag;
  }
  const script = Script.fromString(test.script).encode().toString('hex');
  assert(!test.result.includes('|'));
  assert(test.witness.every((item) => !item.includes(',') && !item.includes('|')));
  lines.push([
    index,
    test.result,
    flags,
    test.value,
    test.locktime,
    test.sequence,
    script,
    test.witness.length,
    test.witness.join(',')
  ].join('|'));
}

fs.writeFileSync(output, `${lines.join('\n')}\n`, 'utf8');
console.log(`wrote ${tests.length} vectors to ${output}`);
