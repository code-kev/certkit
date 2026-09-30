import { describe, expect, it } from 'vitest';
import { validateNames } from '../../src/core/validate.js';

describe('validateNames', () => {
  it.each(['localhost', 'example.com', '*.example.com', 'münich.test'])(
    'accepts DNS/wildcard: %s',
    (n) => {
      expect(validateNames([n])[0]?.kind).toBe('dns');
    },
  );
  it.each(['127.0.0.1', '::1', '192.168.1.1', 'fe80::1'])(
    'accepts IP: %s',
    (n) => {
      expect(validateNames([n])[0]?.kind).toBe('ip');
    },
  );
  it.each([
    '',
    'a..b',
    '*.*.com',
    'exa mple.com',
    '-bad.com',
    'bad-.com',
    '127.0.0.256',
    '*.127.0.0.1',
  ])('rejects: %s', (n) => {
    expect(() => validateNames([n])).toThrowError(
      expect.objectContaining({ code: 'INVALID_NAME' }),
    );
  });
  it('rejects >100 names with NAME_LIMIT', () => {
    const many = Array.from({ length: 101 }, (_, i) => `h${i}.test`);
    expect(() => validateNames(many)).toThrowError(
      expect.objectContaining({ code: 'NAME_LIMIT' }),
    );
  });
  it('rejects an empty name array with INVALID_NAME (v1.10)', () => {
    expect(() => validateNames([])).toThrowError(
      expect.objectContaining({ code: 'INVALID_NAME' }),
    );
  });
  it('normalizes IDN to punycode', () => {
    const r = validateNames(['münich.test'])[0];
    expect(r).toEqual({ kind: 'dns', ascii: 'xn--mnich-kva.test' });
  });
  it.each(['127.1', '0x7f000001', '2130706433', '017700000001'])(
    'classifies shorthand IPv4 %s as ip after normalization (v1.10)',
    (n) => {
      expect(validateNames([n])[0]?.kind).toBe('ip');
    },
  );
  it.each(['::1', 'fe80::1', '::ffff:127.0.0.1'])(
    'accepts raw IPv6 %s as an IP literal before normalization (v1.11 regression guard)',
    (n) => {
      expect(validateNames([n])[0]?.kind).toBe('ip');
    },
  );
  it.each([
    ['::0:0:0', '::'],
    ['0:0:0:0:0:0:0:0', '::'],
    ['2001:0DB8::0001', '2001:db8::1'],
    ['::ffff:127.0.0.1', '::ffff:7f00:1'],
    ['::0:0:0%eth0', '::'],
  ])('canonicalizes IPv6 literal %s to %s', (input, expected) => {
    expect(validateNames([input])[0]).toEqual({ kind: 'ip', ip: expected });
  });
});

describe('DNS length limits', () => {
  const labels = (last: number) =>
    `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(last)}`;

  it('allows DNS and wildcard names up to 253 ASCII characters', () => {
    expect(validateNames([labels(61)])[0]?.kind).toBe('dns');
    expect(validateNames([`*.${labels(59)}`])[0]?.kind).toBe('dns');
  });

  it('rejects DNS names over 253 characters or labels over 63', () => {
    const expandedIdn = [
      ...Array.from({ length: 8 }, () => 'ü'.repeat(21)),
      'ü'.repeat(23),
    ].join('.');
    for (const name of [
      labels(62),
      `${'a'.repeat(64)}.test`,
      `*.${expandedIdn}`,
    ]) {
      expect(() => validateNames([name])).toThrowError(
        expect.objectContaining({ code: 'INVALID_NAME' }),
      );
    }
  });
});
