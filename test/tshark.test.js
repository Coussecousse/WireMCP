const assert = require('node:assert');
const { describe, it } = require('node:test');
const {
  trimPackets, parseTsharkJson, parseIcmpPayloadsFromHex
} = require('../index');

describe('trimPackets', () => {
  it('returns all packets when under maxChars', () => {
    const packets = [{ a: 1 }, { a: 2 }];
    const result = trimPackets(packets, 1000000);
    assert.strictEqual(result.length, 2);
  });

  it('trims packets when over maxChars', () => {
    const bigPayload = 'x'.repeat(5000);
    const packets = Array.from({ length: 1000 }, (_, i) => ({ id: i, data: bigPayload }));
    const result = trimPackets(packets, 10000);
    assert.ok(result.length < 1000);
    assert.ok(result.length > 0);
  });

  it('returns at least 1 packet when over limit', () => {
    const packets = [{ data: 'x'.repeat(100000) }];
    const result = trimPackets(packets, 10);
    assert.strictEqual(result.length, 1);
  });

  it('returns empty array for empty input', () => {
    const result = trimPackets([], 1000);
    assert.strictEqual(result.length, 0);
  });
});

describe('parseTsharkJson', () => {
  it('parses valid JSON array', () => {
    const result = parseTsharkJson('[{"a":1}]');
    assert.deepStrictEqual(result, [{ a: 1 }]);
  });

  it('throws on malformed JSON', () => {
    assert.throws(() => parseTsharkJson('not json'), /Invalid tshark output/);
  });

  it('throws on empty string', () => {
    assert.throws(() => parseTsharkJson(''), /Invalid tshark output/);
  });
});

describe('parseIcmpPayloadsFromHex', () => {
  it('extracts ICMP payload from echo request hex dump', () => {
    const hexDump = [
      'Frame 10: Packet, 61 bytes on wire',
      '    ...',
      '0000  55 c8 33 22 11 00 4c 11 22 33 44 55 08 00 45 00   U.3"..L."3DU..E.',
      '0010  00 2f 12 c7 40 00 40 01 a4 51 c0 a8 01 64 c0 a8   ./..@.@..Q...d..',
      '0020  01 01 08 00 7d ea 42 42 00 00 57 57 39 31 49 48   ....}.BB..WW91IH',
      '0030  4a 6c 59 57 78 73 65 53 42 30 61 47 39            JlYWxseSB0aG9',
      '',
    ].join('\n');

    const result = parseIcmpPayloadsFromHex(hexDump);
    assert.ok(result[10]);
    assert.strictEqual(result[10], '5757393149484A6C5957787365534230614739');
  });

  it('extracts payload from hipercontracer-classified packet', () => {
    const hexDump = [
      'Frame 16: Packet, 61 bytes on wire',
      '    HiPerConTracer Trace Service',
      '0000  55 c8 33 22 11 00 4c 11 22 33 44 55 08 00 45 00   U.3"..L."3DU..E.',
      '0010  00 2f 14 94 40 00 40 01 a2 84 c0 a8 01 64 c0 a8   ./..@.@......d..',
      '0020  01 01 08 00 08 90 42 42 00 01 31 5a 32 68 30 49   ......BB..1Z2h0I',
      '0030  47 6c 30 49 48 64 68 63 79 42 30 61 47            Gl0IHdhcyB0aG',
      '',
    ].join('\n');

    const result = parseIcmpPayloadsFromHex(hexDump);
    assert.ok(result[16]);
    assert.strictEqual(result[16], '315A32683049476C3049486468637942306147');
  });

  it('returns empty object for non-ICMP dump with no payload', () => {
    const hexDump = [
      'Frame 1: Packet, 60 bytes on wire',
      '0000  00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00   ..............E.',
    ].join('\n');

    const result = parseIcmpPayloadsFromHex(hexDump);
    assert.deepStrictEqual(result, {});
  });

  it('handles multiple frames', () => {
    const hexDump = [
      'Frame 10: Packet, 61 bytes on wire',
      '0000  55 c8 33 22 11 00 4c 11 22 33 44 55 08 00 45 00   U.3"..L."3DU..E.',
      '0010  00 2f 12 c7 40 00 40 01 a4 51 c0 a8 01 64 c0 a8   ./..@.@..Q...d..',
      '0020  01 01 08 00 7d ea 42 42 00 00 57 57 39 31 49 48   ....}.BB..WW91IH',
      '0030  4a 6c 59 57 78 73 65 53 42 30 61 47 39            JlYWxseSB0aG9',
      '',
      'Frame 18: Packet, 61 bytes on wire',
      '0000  55 c8 33 22 11 00 4c 11 22 33 44 55 08 00 45 00   U.3"..L."3DU..E.',
      '0010  00 2f 18 15 40 00 40 01 9f 03 c0 a8 01 64 c0 a8   ./..@.@......d..',
      '0020  01 01 08 00 5c c5 42 42 00 02 46 30 49 47 56 68   ....\\.BB..F0IGVh',
      '0030  63 33 6b 67 50 79 42 4a 49 47 64 70 64            c3kgPyBJIGdpd',
      '',
    ].join('\n');

    const result = parseIcmpPayloadsFromHex(hexDump);
    assert.strictEqual(Object.keys(result).length, 2);
    assert.ok(result[10]);
    assert.ok(result[18]);
    assert.notStrictEqual(result[10], result[18]);
  });

  it('extracts correct base64-encodable payload', () => {
    const hexDump = [
      'Frame 10: Packet, 61 bytes on wire',
      '0000  55 c8 33 22 11 00 4c 11 22 33 44 55 08 00 45 00   U.3"..L."3DU..E.',
      '0010  00 2f 12 c7 40 00 40 01 a4 51 c0 a8 01 64 c0 a8   ./..@.@..Q...d..',
      '0020  01 01 08 00 7d ea 42 42 00 00 57 57 39 31 49 48   ....}.BB..WW91IH',
      '0030  4a 6c 59 57 78 73 65 53 42 30 61 47 39            JlYWxseSB0aG9',
      '',
    ].join('\n');

    const result = parseIcmpPayloadsFromHex(hexDump);
    const hex = result[10];
    const ascii = Buffer.from(hex, 'hex').toString('utf8');
    assert.ok(ascii.startsWith('WW91'));
    assert.ok(ascii.length > 0);
    assert.ok(/^[A-Za-z0-9+/]+$/.test(ascii));
  });
});
