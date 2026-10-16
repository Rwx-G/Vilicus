// AC1: for every corpus item, cbor2 decodes the Rust bytes under the profile to the described
// value and hashes the received bytes to the Rust SHA-256; cbor2 also encodes the notation to
// the same bytes and hash. When this runtime's Unicode tables are older than the Rust side's,
// encodings may differ only on items whose text holds a code point this runtime does not
// assign; they are counted and reported, never silently passed.

import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  fromHex,
  hasUnassigned,
  loadVectors,
  matches,
  notationTexts,
  toHex,
  toValue,
  unicodeRelation,
} from '../src/notation.ts';
import type { Notation } from '../src/notation.ts';
import {
  decodeCanonical,
  encodeCanonical,
  LISTED_TAGS,
  MAX_DEPTH,
  sha256Hex,
} from '../src/profile.ts';

interface CorpusItem {
  id: string;
  family: string;
  value: Notation;
  hex: string;
  sha256: string;
}

const corpus = loadVectors<CorpusItem>('corpus.json');
const coreUnicode = String(corpus.profile?.unicode_version);
const relation = unicodeRelation(coreUnicode);

function skewEligible(item: CorpusItem): boolean {
  return relation === 'runtime-older' && notationTexts(item.value).some(hasUnassigned);
}

test('the corpus header states the same profile constants', () => {
  assert.equal(corpus.format, 'vilicus-e19-corpus/1');
  assert.equal(corpus.profile?.max_depth, MAX_DEPTH);
  assert.deepEqual(corpus.profile?.listed_tags, LISTED_TAGS.map(Number));
  console.log(`CHECK INFO unicode rust ${coreUnicode} runtime ${process.versions.unicode} (${relation})`);
  assert.notEqual(relation, 'runtime-newer', 'this harness classifies a skew only when the runtime is older');
  if (process.env.REQUIRE_SAME_UNICODE === '1') {
    assert.equal(relation, 'same', 'run.sh pins a Node whose Unicode version matches the Rust tables');
  }
});

test('cbor2 decodes every Rust encoding under the profile to the described value', () => {
  for (const item of corpus.items) {
    const bytes = fromHex(item.hex);
    assert.equal(sha256Hex(bytes), item.sha256, `${item.id}: hash of received bytes`);
    const decoded = decodeCanonical(bytes);
    assert.ok(matches(decoded, item.value, skewEligible(item)), `${item.id}: decoded value`);
  }
  console.log(`CHECK INFO ts decoded corpus items ${corpus.items.length}`);
});

test('cbor2 encodes every corpus value to the Rust bytes and hash', () => {
  const skewed: string[] = [];
  for (const item of corpus.items) {
    const bytes = encodeCanonical(toValue(item.value));
    if (toHex(bytes) !== item.hex && skewEligible(item)) {
      skewed.push(item.id);
      continue;
    }
    assert.equal(toHex(bytes), item.hex, `${item.id}: encoding`);
    assert.equal(sha256Hex(bytes), item.sha256, `${item.id}: hash`);
  }
  console.log(`CHECK INFO ts encoded corpus items ${corpus.items.length}, unicode-skewed ${skewed.length}: ${skewed.join(' ')}`);
});
