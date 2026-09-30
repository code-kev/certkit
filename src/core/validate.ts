import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';
import { CertkitError } from './errors.js';

export type ValidName =
  | { kind: 'dns'; ascii: string }
  | { kind: 'ip'; ip: string };

/**
 * The X.509 SAN encoder parses IP strings itself, so a non-canonical IPv6
 * literal (for example the IPv4-mapped `::ffff:127.0.0.1`) is encoded as the
 * wrong address and breaks the cache identity. Canonicalize here, the shared
 * boundary every caller routes through. A zone-id suffix (`%eth0`) is
 * stripped: the SAN carries the address, never the zone.
 */
function canonicalIp(ip: string): string {
  const [address = ip] = ip.split('%');
  if (isIP(address) !== 6) return address;
  try {
    return new URL(`http://[${address}]/`).hostname.slice(1, -1);
  } catch {
    // Not URL-parseable; the SAN encoder rejects or handles the raw form.
    return address;
  }
}

export function validateNames(names: string[]): ValidName[] {
  if (names.length > 100)
    throw new CertkitError('NAME_LIMIT', 'At most 100 names may be validated.');
  if (names.length === 0)
    throw new CertkitError('INVALID_NAME', 'At least one name is required.');

  return names.map((name) => {
    const wildcard = name.startsWith('*.');
    const input = wildcard ? name.slice(2) : name;
    if (!wildcard && isIP(input)) return { kind: 'ip', ip: canonicalIp(input) };

    const ascii = domainToASCII(input);
    if (!ascii) throw new CertkitError('INVALID_NAME', `Invalid name: ${name}`);
    if (isIP(ascii)) {
      if (!wildcard) return { kind: 'ip', ip: canonicalIp(ascii) };
      throw new CertkitError(
        'INVALID_NAME',
        `Wildcard names cannot contain an IP address: ${name}`,
      );
    }

    const labels = ascii.split('.');
    if (
      (wildcard ? ascii.length + 2 : ascii.length) > 253 ||
      labels.some((label) => !/^(?!-)[a-z0-9-]{1,63}(?<!-)$/.test(label))
    ) {
      throw new CertkitError('INVALID_NAME', `Invalid name: ${name}`);
    }
    return { kind: 'dns', ascii: wildcard ? `*.${ascii}` : ascii };
  });
}
