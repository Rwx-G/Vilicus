// The AD-13 canonical profile on top of cbor2, the TypeScript side of the Rust `profile`
// module. cbor2's dCBOR decode options enforce the deterministic encoding (shortest heads,
// definite lengths, sorted unique map keys, no trailing bytes, NFC text, simple values limited
// to false, true and null, integers not below -2^63). This module adds what the profile states
// beyond that, with the same semantics as the Rust side: no float, no tag outside LISTED_TAGS,
// the nesting bound checked before cbor2 recurses (its own maxDepth counts an array level
// twice and a map or tag level once, so it cannot express the profile's bound), a
// re-encoding comparison as a backstop for any canonicality gap, and, on encode, refusal of
// non-NFC text instead of cbor2's silent normalization.

import { createHash } from 'node:crypto';
import { decode, encode } from 'cbor2';
import type { DecodeOptions, EncodeOptions } from 'cbor2';

/** Most arrays and maps an item may sit in, counting itself when it is one. */
export const MAX_DEPTH = 32;

/** Tags a hashed or signed type may carry. Empty: no Vilicus type needs one yet. */
export const LISTED_TAGS: readonly bigint[] = [];

export class Rejection extends Error {}

const DECODE_OPTIONS: DecodeOptions = {
  dcbor: true,
  // The dCBOR preset turns integers above 2^53 into lossy JS numbers; a signer must display
  // the exact value, so they stay bigints.
  convertUnsafeIntsToFloat: false,
  rejectFloats: true,
  rejectBigInts: true,
  ignoreGlobalTags: true,
  preferMap: true,
};

// No `ignoreGlobalTags` here: on encode it also drops the built-in Array, Map and Uint8Array
// encoders, and arrays then encode as empty maps.
const ENCODE_OPTIONS: EncodeOptions = {
  dcbor: true,
  rejectFloats: true,
  rejectBigInts: true,
};

interface Head {
  major: number;
  width: number;
  argument: bigint;
  next: number;
}

function readHead(bytes: Uint8Array, pos: number): Head {
  if (pos >= bytes.length) {
    throw new Rejection('malformed: input ends before an item');
  }
  const initial = bytes[pos];
  const major = initial >> 5;
  const additional = initial & 0x1f;
  let width: number;
  if (additional <= 23) {
    width = 0;
  } else if (additional <= 27) {
    width = 1 << (additional - 24);
  } else if (additional === 31) {
    throw new Rejection('malformed: indefinite length or break');
  } else {
    throw new Rejection('malformed: reserved additional information');
  }
  const start = pos + 1;
  if (start + width > bytes.length) {
    throw new Rejection('malformed: input ends inside a head');
  }
  let argument = BigInt(additional);
  if (width > 0) {
    argument = 0n;
    for (let i = start; i < start + width; i++) {
      argument = (argument << 8n) | BigInt(bytes[i]);
    }
  }
  return { major, width, argument, next: start + width };
}

/**
 * Walks the item heads without recursion and refuses an input nested deeper than MAX_DEPTH
 * (arrays, maps and tags each count a level), carrying an unlisted tag or a float, or followed
 * by trailing bytes. `listed` exists for tests; the profile uses LISTED_TAGS.
 */
export function scanHeads(bytes: Uint8Array, listed: readonly bigint[] = LISTED_TAGS): void {
  // Items still expected in each open container; the bottom entry stands for the root.
  const expected: bigint[] = [1n];
  let pos = 0;
  while (expected.length > 0) {
    const top = expected.length - 1;
    if (expected[top] === 0n) {
      expected.pop();
      continue;
    }
    expected[top] -= 1n;
    const head = readHead(bytes, pos);
    pos = head.next;
    switch (head.major) {
      case 2:
      case 3:
        if (head.argument > BigInt(bytes.length - pos)) {
          throw new Rejection('malformed: string runs past the input');
        }
        pos += Number(head.argument);
        break;
      case 4:
      case 5:
      case 6:
        if (head.major === 6 && !listed.includes(head.argument)) {
          throw new Rejection(`unlisted tag ${head.argument}`);
        }
        // `expected` holds the root entry, so its length is the depth of the new item.
        if (expected.length > MAX_DEPTH) {
          throw new Rejection(`more than ${MAX_DEPTH} nested arrays, maps or tags`);
        }
        // A tag is a level holding exactly one item.
        expected.push(head.major === 4 ? head.argument : head.major === 5 ? head.argument * 2n : 1n);
        break;
      case 7:
        if (head.width >= 2) {
          throw new Rejection('floating-point value');
        }
        break;
    }
  }
  if (pos !== bytes.length) {
    throw new Rejection('bytes after the first item');
  }
}

/** Refuses a decoded value whose re-encoding differs from the bytes it came from. */
export function requireRoundTrip(value: unknown, bytes: Uint8Array): void {
  let encoded: Uint8Array;
  try {
    encoded = encode(value, ENCODE_OPTIONS);
  } catch (error) {
    throw new Rejection(`re-encoding failed: ${(error as Error).message}`);
  }
  if (!equalBytes(encoded, bytes)) {
    throw new Rejection('re-encoding differs from the input');
  }
}

/** Decodes bytes received from the Core, refusing anything outside the profile. */
export function decodeCanonical(bytes: Uint8Array): unknown {
  scanHeads(bytes);
  let value: unknown;
  try {
    value = decode(bytes, DECODE_OPTIONS);
  } catch (error) {
    throw new Rejection(`not deterministic: ${(error as Error).message}`);
  }
  requireRoundTrip(value, bytes);
  return value;
}

/** Refuses text that is not NFC under this runtime's tables, wherever it sits in the value. */
function requireNfc(value: unknown): void {
  if (typeof value === 'string') {
    if (value !== value.normalize('NFC')) {
      throw new Rejection('text not in Unicode Normalization Form C');
    }
  } else if (Array.isArray(value)) {
    value.forEach(requireNfc);
  } else if (value instanceof Map) {
    for (const [key, item] of value) {
      requireNfc(key);
      requireNfc(item);
    }
  }
}

/**
 * Encodes a value with the profile encoder. Used by the spike only: a signer never encodes.
 * Non-NFC text is refused rather than normalized, so two keys equal once normalized cannot
 * collapse into one entry; cbor2's own duplicate-key check is a second guard.
 */
export function encodeCanonical(value: unknown): Uint8Array {
  requireNfc(value);
  let bytes: Uint8Array;
  try {
    bytes = encode(value, ENCODE_OPTIONS);
  } catch (error) {
    throw new Rejection(`not encodable: ${(error as Error).message}`);
  }
  scanHeads(bytes);
  return bytes;
}

/** cbor2 with its dCBOR decode options alone, for the record of what this module adds. */
export function decodeWithLibraryOnly(bytes: Uint8Array): unknown {
  return decode(bytes, { dcbor: true, convertUnsafeIntsToFloat: false });
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}
