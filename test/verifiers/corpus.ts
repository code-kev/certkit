export type SanEntry =
  | { type: 'dns'; value: string }
  | { type: 'ip'; value: string };

export interface CorpusCase {
  /** Stable identifier used in test names and temp paths. */
  id: string;
  /** Names handed to certificateFor; may be unicode or shorthand input. */
  names: string[];
  validityDays: number;
  /** Normalized SAN entries the minted leaf must carry (certificate order). */
  san: SanEntry[];
  /** openssl x509 rendering of the SAN line, for the field-text oracle. */
  opensslSan: string;
  /** Expected leaf subject common name (normalized, lowercase, with wildcard). */
  commonName: string;
  /** Host/ip every verifying oracle must accept the leaf for. */
  verifyHost: { kind: 'hostname' | 'ip'; value: string };
}

/** Every corpus leaf must carry exactly these extension values. */
export const expectedKeyUsage = 'Digital Signature';
export const expectedExtendedKeyUsage = 'TLS Web Server Authentication';
export const notBeforeSkewMs = 5 * 60_000;

/**
 * Minted-certificate cases exercised against every available oracle. The SAN
 * table is the certificate-order golden, independent of validateNames output.
 */
export const corpus: readonly CorpusCase[] = [
  {
    id: 'single-dns',
    names: ['localhost'],
    validityDays: 30,
    san: [{ type: 'dns', value: 'localhost' }],
    opensslSan: 'DNS:localhost',
    commonName: 'localhost',
    verifyHost: { kind: 'hostname', value: 'localhost' },
  },
  {
    id: 'wildcard-dns',
    names: ['*.example.com'],
    validityDays: 30,
    san: [{ type: 'dns', value: '*.example.com' }],
    opensslSan: 'DNS:*.example.com',
    commonName: '*.example.com',
    verifyHost: { kind: 'hostname', value: 'app.example.com' },
  },
  {
    id: 'idn-punycode',
    names: ['münich.test'],
    validityDays: 30,
    san: [{ type: 'dns', value: 'xn--mnich-kva.test' }],
    opensslSan: 'DNS:xn--mnich-kva.test',
    commonName: 'xn--mnich-kva.test',
    verifyHost: { kind: 'hostname', value: 'xn--mnich-kva.test' },
  },
  {
    id: 'ipv4',
    names: ['127.0.0.1'],
    validityDays: 30,
    san: [{ type: 'ip', value: '127.0.0.1' }],
    opensslSan: 'IP Address:127.0.0.1',
    commonName: '127.0.0.1',
    verifyHost: { kind: 'ip', value: '127.0.0.1' },
  },
  {
    id: 'ipv6',
    names: ['2001:db8::1'],
    validityDays: 30,
    san: [{ type: 'ip', value: '2001:db8::1' }],
    opensslSan: 'IP Address:2001:DB8:0:0:0:0:0:1',
    commonName: '2001:db8::1',
    verifyHost: { kind: 'ip', value: '2001:db8::1' },
  },
  {
    id: 'mixed-set',
    names: ['localhost', '*.example.com', 'münich.test', '127.0.0.1', '::1'],
    validityDays: 825,
    san: [
      { type: 'dns', value: '*.example.com' },
      { type: 'ip', value: '127.0.0.1' },
      { type: 'ip', value: '::1' },
      { type: 'dns', value: 'localhost' },
      { type: 'dns', value: 'xn--mnich-kva.test' },
    ],
    opensslSan:
      'DNS:*.example.com, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1, DNS:localhost, DNS:xn--mnich-kva.test',
    commonName: '*.example.com',
    verifyHost: { kind: 'hostname', value: 'localhost' },
  },
  {
    id: 'validity-825-boundary',
    names: ['localhost'],
    validityDays: 825,
    san: [{ type: 'dns', value: 'localhost' }],
    opensslSan: 'DNS:localhost',
    commonName: 'localhost',
    verifyHost: { kind: 'hostname', value: 'localhost' },
  },
  {
    id: 'validity-minimum',
    names: ['localhost'],
    validityDays: 1,
    san: [{ type: 'dns', value: 'localhost' }],
    opensslSan: 'DNS:localhost',
    commonName: 'localhost',
    verifyHost: { kind: 'hostname', value: 'localhost' },
  },
];
