// AC2: the hand-written invalid inputs are all refused, and every fuzzed input gets the verdict
// the Rust profile decoder recorded; an accepted input re-encodes to itself. When this
// runtime's Unicode tables are older than the Rust side's, a verdict may differ only on an NFC
// refusal of text holding a code point this runtime does not assign; such cases are counted
// and reported.

import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  fromHex,
  hasUnassigned,
  loadVectors,
  toHex,
  unicodeRelation,
  vectorsDir,
} from '../src/notation.ts';
import {
  decodeCanonical,
  decodeWithLibraryOnly,
  encodeCanonical,
  MAX_DEPTH,
  Rejection,
} from '../src/profile.ts';
import { toValue } from '../src/notation.ts';
import type { Notation } from '../src/notation.ts';

interface InvalidItem {
  name: string;
  hex: string;
  rule: string;
}

interface FuzzItem {
  id: string;
  kind: string;
  hex: string;
  must_reject: boolean;
  accept: boolean;
  rust: string;
}

function verdict(bytes: Uint8Array): { accepted: boolean; value?: unknown; reason?: string } {
  try {
    return { accepted: true, value: decodeCanonical(bytes) };
  } catch (error) {
    assert.ok(error instanceof Rejection, `unexpected error type: ${error}`);
    return { accepted: false, reason: error.message };
  }
}

test('every hand-written invalid input is refused', { skip: !existsSync(join(vectorsDir(), 'invalid.json')) }, () => {
  const invalid = loadVectors<InvalidItem>('invalid.json');
  const libraryAccepts: string[] = [];
  for (const item of invalid.items) {
    const bytes = fromHex(item.hex);
    assert.equal(verdict(bytes).accepted, false, `${item.name} (${item.rule}): accepted`);
    try {
      decodeWithLibraryOnly(bytes);
      libraryAccepts.push(item.name);
    } catch {
      // Refused by cbor2 alone.
    }
  }
  console.log(`CHECK INFO ts invalid items ${invalid.items.length}`);
  console.log(`CHECK INFO cbor2 alone accepts: ${libraryAccepts.join(' ')}`);
});

test('every encode-invalid value is refused by the profile encoder', () => {
  const invalid = loadVectors<{ name: string; value: Notation }>('encode-invalid.json');
  for (const item of invalid.items) {
    assert.throws(() => encodeCanonical(toValue(item.value)), Rejection, `${item.name}: encoded`);
  }
  console.log(`CHECK INFO ts encode-invalid items ${invalid.items.length}`);
});

test('every fuzzed input gets the Rust verdict', () => {
  const fuzz = loadVectors<FuzzItem>('fuzz.json');
  assert.equal(fuzz.profile?.max_depth, MAX_DEPTH);
  const runtimeOlder = unicodeRelation(String(fuzz.profile?.unicode_version)) === 'runtime-older';
  let accepted = 0;
  const disagreements: string[] = [];
  const skewed: string[] = [];
  for (const item of fuzz.items) {
    const bytes = fromHex(item.hex);
    const result = verdict(bytes);
    // In a disagreement exactly one side refuses, so the condition is on that side's reason.
    const refusalIsNfc = item.accept
      ? /normalized|Normalization Form C/.test(result.reason ?? '')
      : /Normalization Form C/.test(item.rust);
    if (result.accepted !== item.accept && runtimeOlder && refusalIsNfc &&
      hasUnassigned(new TextDecoder().decode(bytes))) {
      skewed.push(item.id);
      continue;
    }
    if (result.accepted !== item.accept) {
      disagreements.push(`${item.id} ${item.kind} ${item.hex.slice(0, 80)} rust=${item.rust} ts=${result.reason ?? 'accept'}`);
      continue;
    }
    if (item.must_reject) {
      assert.equal(item.accept, false, `${item.id}: targeted mutation marked accepted`);
    }
    if (result.accepted) {
      assert.equal(toHex(encodeCanonical(result.value)), item.hex, `${item.id}: re-encoding`);
      accepted += 1;
    }
  }
  assert.deepEqual(disagreements, [], `verdicts differ:\n${disagreements.slice(0, 20).join('\n')}`);
  console.log(`CHECK INFO ts fuzz accepted ${accepted} rejected ${fuzz.items.length - accepted - skewed.length}, unicode-skewed ${skewed.length}: ${skewed.join(' ')}`);
});
