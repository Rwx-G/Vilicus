// Unit tests of the TypeScript profile layer, mirroring the Rust unit tests of `profile.rs`.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Tag } from 'cbor2';

import { fromHex } from '../src/notation.ts';
import {
  decodeCanonical,
  encodeCanonical,
  MAX_DEPTH,
  Rejection,
  requireRoundTrip,
  scanHeads,
} from '../src/profile.ts';

function repeated(byte: number, count: number, last: number[]): Uint8Array {
  return Uint8Array.from([...new Array<number>(count).fill(byte), ...last]);
}

test('listed tags count toward depth', () => {
  const listed = [1n];
  assert.doesNotThrow(() => scanHeads(repeated(0xc1, MAX_DEPTH, [0x00]), listed));
  assert.throws(() => scanHeads(repeated(0xc1, MAX_DEPTH + 1, [0x00]), listed), /nested/);
});

test('trailing bytes are refused by the scan', () => {
  const bytes = Uint8Array.from([0x00, ...new Array<number>(100_000).fill(0x81)]);
  assert.throws(() => scanHeads(bytes), /after the first item/);
  assert.throws(() => decodeCanonical(bytes), Rejection);
});

test('the round-trip comparison refuses a reduced float', () => {
  // The value dcbor makes of fb43e0000000000001 (finding 1), against those bytes.
  const reduced = 2n ** 63n + 2048n;
  assert.throws(() => requireRoundTrip(reduced, fromHex('fb43e0000000000001')), /differs/);
  assert.doesNotThrow(() => requireRoundTrip(reduced, fromHex('1b8000000000000800')));
});

test('encode refuses values outside the profile', () => {
  let deep: unknown = [];
  for (let i = 0; i < MAX_DEPTH; i++) deep = [deep];
  for (const value of [1.5, new Tag(0, 0), deep, 'café', new Map([['café', 1], ['café', 2]])]) {
    assert.throws(() => encodeCanonical(value), Rejection);
  }
});

test('a signer with newer Unicode tables refuses marks an older Core left unordered', () => {
  // From random-00145 and fuzz-036083: U+1AE1 and U+1AD5 are combining marks new in Unicode
  // 17. A Core on Unicode 16 tables sees unassigned code points and leaves them before a
  // known mark; a signer on Unicode 17 or later must reorder them, so it refuses the bytes
  // (fails closed), while a signer on Unicode 16 accepts them.
  const fromOlderCore = ['6661e1aba1ccb7', '6661e1ab95ccac'];
  const [major] = (process.versions.unicode ?? '0').split('.').map(Number);
  for (const hex of fromOlderCore) {
    if (major >= 17) {
      assert.throws(() => decodeCanonical(fromHex(hex)), /normalized/, hex);
    } else {
      assert.doesNotThrow(() => decodeCanonical(fromHex(hex)), hex);
    }
  }
  console.log(`CHECK INFO ts unicode ${process.versions.unicode}: bytes from an older Core ${major >= 17 ? 'refused' : 'accepted'}`);
});
