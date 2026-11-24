import { describe, it, expect } from 'vitest';
import {
  encodeMessage,
  decodeMessage,
  validateClientRequest,
  MESSAGE_TYPES as T,
  MAX_FILE_BYTES,
  MAX_JSON_BYTES,
  HEADER_BYTES,
} from '@securetransfer/protocol';

const probe = () => encodeMessage(T.PROBE, 1, { sequence: 7 });
describe('32-byte shared protocol', () => {
  it('matches an independent big-endian fixture, including an unsigned 64-bit ID', () => {
    const bytes = encodeMessage(
      T.FILE_CHUNK,
      0,
      new Uint8Array([0xaa, 0xbb]),
      0xffffffffffffffffn,
      65536n,
    );
    expect(Buffer.from(bytes).toString('hex')).toBe(
      '534654310130000000000000ffffffffffffffff000000000001000000000002aabb',
    );
    const decoded = decodeMessage(bytes);
    expect(decoded.header.transferId).toBe(0xffffffffffffffffn);
    expect(decoded.header.offset).toBe(65536n);
    expect(decoded.payload).toEqual(new Uint8Array([0xaa, 0xbb]));
  });
  it('decodes a view with a nonzero byte offset', () => {
    const packet = probe();
    const buffer = new Uint8Array(packet.length + 9);
    buffer.set(packet, 5);
    expect(decodeMessage(buffer.subarray(5, 5 + packet.length)).json).toEqual({ sequence: 7 });
  });
  it.each([
    ['magic', 0, 0],
    ['version', 4, 2],
    ['type', 5, 0xff],
    ['flags', 7, 1],
    ['length', 31, 0xff],
  ])('rejects invalid %s', (_name, offset, value) => {
    const bytes = probe();
    bytes[offset as number] = value as number;
    expect(() => decodeMessage(bytes)).toThrow();
  });
  it.each([0, 31])('rejects truncated header (%s bytes)', (length) => {
    expect(() => decodeMessage(probe().subarray(0, length))).toThrow();
  });
  it('rejects trailing bytes and concatenated application messages', () => {
    const packet = probe();
    const bytes = new Uint8Array(packet.length * 2);
    bytes.set(packet);
    bytes.set(packet, packet.length);
    expect(() => decodeMessage(bytes)).toThrow('length');
  });
  it('checks JSON objects, UTF-8 and control size', () => {
    for (const payload of [
      new TextEncoder().encode('[]'),
      new Uint8Array([0xff]),
      new TextEncoder().encode('null'),
    ]) {
      expect(() => encodeMessage(T.PROBE, 1, payload)).toThrow();
    }
    expect(() => encodeMessage(T.PROBE, 1, { text: 'x'.repeat(MAX_JSON_BYTES) })).toThrow();
  });
  it('enforces block size, ACK emptiness, and offset limits', () => {
    expect(() => encodeMessage(T.FILE_CHUNK, 0, new Uint8Array(), 1n)).toThrow();
    expect(() => encodeMessage(T.FILE_CHUNK, 0, new Uint8Array(65537), 1n)).toThrow();
    expect(() => encodeMessage(T.CHUNK_ACK, 0, {}, 1n)).toThrow();
    expect(() =>
      encodeMessage(T.FILE_CHUNK, 0, new Uint8Array([1]), 1n, BigInt(MAX_FILE_BYTES)),
    ).toThrow();
    expect(decodeMessage(encodeMessage(T.CHUNK_ACK, 0, new Uint8Array(), 1n)).payload.length).toBe(
      0,
    );
    expect(() => encodeMessage(T.PROBE, 0x100000000, {})).toThrow();
    expect(() => encodeMessage(T.PROBE, 1, {}, -1n)).toThrow();
  });
  it('reserves zero IDs and protects unauthenticated operations', () => {
    expect(() => validateClientRequest(decodeMessage(probe()), 'CONNECTED')).not.toThrow();
    expect(() =>
      validateClientRequest(decodeMessage(encodeMessage(T.PROBE, 0, { sequence: 1 })), 'CONNECTED'),
    ).toThrow();
    expect(() =>
      validateClientRequest(decodeMessage(encodeMessage(T.LIST_FILES, 2)), 'CONNECTED'),
    ).toThrow('Authentication');
    expect(() =>
      validateClientRequest(
        decodeMessage(encodeMessage(T.FILE_CHUNK, 0, new Uint8Array([1]), 1n)),
        'CONNECTED',
      ),
    ).toThrow('Authentication');
    expect(() => validateClientRequest(decodeMessage(probe()), 'CLOSED')).toThrow();
  });
  it('validates required fields without claiming to authenticate', () => {
    expect(() =>
      validateClientRequest(
        decodeMessage(encodeMessage(T.LOGIN, 1, { username: 'abc', password: '12345678' })),
        'CONNECTED',
      ),
    ).not.toThrow();
    expect(() =>
      validateClientRequest(decodeMessage(encodeMessage(T.LOGIN, 1, {})), 'CONNECTED'),
    ).toThrow();
    expect(() =>
      validateClientRequest(
        decodeMessage(encodeMessage(T.AUTH_RESUME, 1, { token: 'bad' })),
        'CONNECTED',
      ),
    ).toThrow();
    expect(() =>
      validateClientRequest(
        decodeMessage(encodeMessage(T.PROBE, 1, { sequence: -1 })),
        'CONNECTED',
      ),
    ).toThrow();
    expect(HEADER_BYTES).toBe(32);
  });
});
