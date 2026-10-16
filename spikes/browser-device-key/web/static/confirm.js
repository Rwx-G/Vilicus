// Spike E22: the browser's check before it signs a light confirmation. The device key signs
// only bytes that decode as canonical CBOR (the AD-13 profile's round-trip test, with cbor2's
// dCBOR options as in story 1.9) into a confirmation challenge for the request the member is
// approving and for this device. Without it, the page would sign whatever bytes the server
// returned.

import { decode, encode } from 'cbor2';
import { sameBytes } from './common.js';

export const CONFIRMATION_KIND = 'vilicus/v1/light-confirmation';

const DECODE_OPTIONS = {
  dcbor: true,
  convertUnsafeIntsToFloat: false,
  rejectFloats: true,
  rejectBigInts: true,
  ignoreGlobalTags: true,
  preferMap: true,
};
const ENCODE_OPTIONS = { dcbor: true, rejectFloats: true, rejectBigInts: true };

export function encodeCanonical(value) {
  return encode(value, ENCODE_OPTIONS);
}

export function decodeCanonical(bytes) {
  const value = decode(bytes, DECODE_OPTIONS);
  if (!sameBytes(encodeCanonical(value), bytes)) throw new Error('not canonical');
  return value;
}

// Returns 'ok' or `refused:<reason>`.
export function checkConfirmation(bytes, requestId, deviceId) {
  let value;
  try {
    value = decodeCanonical(bytes);
  } catch {
    return 'refused:not_canonical_cbor';
  }
  if (!(value instanceof Map)) return 'refused:not_a_map';
  if (value.get('kind') !== CONFIRMATION_KIND) return 'refused:wrong_kind';
  if (value.get('decision') !== 'approve') return 'refused:wrong_decision';
  if (!sameBytes(value.get('request_id'), requestId)) return 'refused:other_request';
  if (!sameBytes(value.get('device_id'), deviceId)) return 'refused:other_device';
  return 'ok';
}
