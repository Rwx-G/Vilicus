// The language-neutral value notation of the vector files (see the Rust `notation` module):
// building the JS value an encoder takes, and comparing a decoded value with a notation.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export type Notation =
  | { int: string }
  | { bytes: string }
  | { text: string }
  | { array: Notation[] }
  | { map: [Notation, Notation][] }
  | { simple: 'false' | 'true' | 'null' };

export interface VectorFile<T> {
  format: string;
  profile?: Record<string, unknown>;
  items: T[];
}

export function vectorsDir(): string {
  return process.env.VECTORS_DIR ?? join(import.meta.dirname, '..', '..', 'vectors');
}

export function loadVectors<T>(name: string): VectorFile<T> {
  return JSON.parse(readFileSync(join(vectorsDir(), name), 'utf8')) as VectorFile<T>;
}

export function fromHex(hex: string): Uint8Array {
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

export function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

function intValue(text: string): number | bigint {
  const value = BigInt(text);
  return value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER)
    ? Number(value)
    : value;
}

/** The JS value cbor2 encodes for a notation: map entries in notation order, text as is. */
export function toValue(notation: Notation): unknown {
  if ('int' in notation) return intValue(notation.int);
  if ('bytes' in notation) return fromHex(notation.bytes);
  if ('text' in notation) return notation.text;
  if ('array' in notation) return notation.array.map(toValue);
  if ('map' in notation) {
    return new Map(notation.map.map(([key, value]) => [toValue(key), toValue(value)]));
  }
  return { false: false, true: true, null: null }[notation.simple];
}

/**
 * Whether two texts differ only at positions where one of them holds a code point the
 * runtime's Unicode tables do not assign, which is how NFC under older tables differs.
 */
function differsOnlyAtUnassigned(a: string, b: string): boolean {
  const left = [...a];
  const right = [...b];
  return left.length === right.length &&
    left.every((point, i) => point === right[i] || hasUnassigned(point) || hasUnassigned(right[i]));
}

/**
 * Whether a decoded value is the value a notation describes, text compared with the
 * notation's text in NFC under this runtime's tables. With `skewed`, the two may also differ,
 * but only at positions holding a code point this runtime does not assign.
 */
export function matches(decoded: unknown, notation: Notation, skewed = false): boolean {
  if ('int' in notation) {
    return (typeof decoded === 'number' || typeof decoded === 'bigint') &&
      BigInt(decoded) === BigInt(notation.int);
  }
  if ('bytes' in notation) {
    return decoded instanceof Uint8Array && toHex(decoded) === notation.bytes;
  }
  if ('text' in notation) {
    const expected = notation.text.normalize('NFC');
    return typeof decoded === 'string' &&
      (decoded === expected || (skewed && differsOnlyAtUnassigned(decoded, expected)));
  }
  if ('array' in notation) {
    return Array.isArray(decoded) && decoded.length === notation.array.length &&
      notation.array.every((item, i) => matches(decoded[i], item, skewed));
  }
  if ('map' in notation) {
    if (!(decoded instanceof Map) || decoded.size !== notation.map.length) return false;
    const entries = [...decoded.entries()];
    return notation.map.every(([key, value]) =>
      entries.some(([k, v]) => matches(k, key, skewed) && matches(v, value, skewed)));
  }
  return decoded === toValue(notation);
}

/**
 * How the runtime's Unicode version compares with the one the Rust side normalized with.
 * NFC depends on the Unicode tables, so a version skew can change NFC results for text
 * containing code points whose normalization data differs between the two versions.
 */
export function unicodeRelation(coreVersion: string): 'same' | 'runtime-older' | 'runtime-newer' {
  const parse = (version: string) => version.split('.').map(Number);
  const [coreMajor, coreMinor] = parse(coreVersion);
  const [major, minor] = parse(process.versions.unicode ?? '0.0');
  if (major === coreMajor && minor === coreMinor) return 'same';
  return major < coreMajor || (major === coreMajor && minor < coreMinor)
    ? 'runtime-older'
    : 'runtime-newer';
}

/** Whether the text holds a code point the runtime's Unicode tables do not assign. */
export function hasUnassigned(text: string): boolean {
  return /\p{Cn}/u.test(text);
}

export function notationTexts(notation: Notation): string[] {
  if ('text' in notation) return [notation.text];
  if ('array' in notation) return notation.array.flatMap(notationTexts);
  if ('map' in notation) return notation.map.flatMap(([k, v]) => [...notationTexts(k), ...notationTexts(v)]);
  return [];
}
