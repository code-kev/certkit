import '../reflect-metadata.js';
import { createHash, randomBytes, randomInt, webcrypto } from 'node:crypto';
import {
  BasicConstraintsExtension,
  ExtendedKeyUsage,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  X509Certificate,
  X509CertificateGenerator,
} from '@peculiar/x509';
import { CertkitError } from './errors.js';
import type { ValidName } from './validate.js';

const DAY_MS = 86_400_000;
const NOT_BEFORE_SKEW_MS = 5 * 60_000;
const MAX_LEAF_VALIDITY_DAYS = 825;
type GeneratedKeyPair = { publicKey: CryptoKey; privateKey: CryptoKey };

export interface CaMaterial {
  keyPem: string;
  certPem: string;
  subject: string;
  serial: string;
  expiresAt: string;
}

function markerForSubject(userMarker: string): string {
  return /^[A-Za-z0-9-]+$/.test(userMarker)
    ? userMarker
    : createHash('sha256').update(userMarker).digest('hex').slice(0, 12);
}

function randomSerial(): string {
  const bytes = randomBytes(9);
  bytes[0] = randomInt(1, 128);
  return bytes.toString('hex');
}

function privateKeyPem(pkcs8: ArrayBuffer): string {
  const base64 = Buffer.from(pkcs8).toString('base64');
  const body = base64.match(/.{1,64}/g)?.join('\n') ?? '';
  return `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----\n`;
}

function pkcs8FromPem(keyPem: string): Uint8Array<ArrayBuffer> {
  const base64 = keyPem.replace(
    /-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----|\s+/g,
    '',
  );
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

async function generateKeys(): Promise<GeneratedKeyPair> {
  // Keys are serialized for storage, so they must be exportable; T6 writes them 0600.
  return (await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  )) as GeneratedKeyPair;
}

function generationError(cause: unknown): CertkitError {
  return cause instanceof CertkitError
    ? cause
    : new CertkitError('GENERATION_FAILED', 'Certificate generation failed.', {
        cause,
      });
}

export async function mintCa(userMarker: string): Promise<CaMaterial> {
  try {
    const keys = await generateKeys();
    const notBefore = new Date(Date.now() - NOT_BEFORE_SKEW_MS);
    const cert = await X509CertificateGenerator.createSelfSigned(
      {
        serialNumber: randomSerial(),
        name: `CN=certkit development CA, OU=${markerForSubject(userMarker)}`,
        notBefore,
        notAfter: new Date(notBefore.getTime() + 3650 * DAY_MS),
        signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
        keys,
        extensions: [
          new BasicConstraintsExtension(true, 0, true),
          new KeyUsagesExtension(
            KeyUsageFlags.digitalSignature |
              KeyUsageFlags.keyCertSign |
              KeyUsageFlags.cRLSign,
            true,
          ),
        ],
      },
      webcrypto,
    );
    return {
      keyPem: privateKeyPem(
        await webcrypto.subtle.exportKey('pkcs8', keys.privateKey),
      ),
      certPem: cert.toString('pem'),
      subject: cert.subject,
      serial: cert.serialNumber,
      expiresAt: cert.notAfter.toISOString(),
    };
  } catch (cause) {
    throw generationError(cause);
  }
}

export async function mintLeaf(
  ca: CaMaterial,
  names: ValidName[],
  validityDays: number,
): Promise<{ keyPem: string; certPem: string; expiresAt: string }> {
  if (
    !Number.isInteger(validityDays) ||
    validityDays < 1 ||
    validityDays > MAX_LEAF_VALIDITY_DAYS
  ) {
    throw new CertkitError(
      'INVALID_OPTIONS',
      `Leaf validity must be an integer between 1 and ${MAX_LEAF_VALIDITY_DAYS} days.`,
    );
  }
  const commonName = names[0];
  if (!commonName)
    throw new CertkitError('INVALID_NAME', 'At least one name is required.');

  try {
    const caCert = new X509Certificate(ca.certPem);
    const caKey = await webcrypto.subtle.importKey(
      'pkcs8',
      pkcs8FromPem(ca.keyPem),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign'],
    );
    const keys = await generateKeys();
    const notBefore = new Date(Date.now() - NOT_BEFORE_SKEW_MS);
    const cert = await X509CertificateGenerator.create(
      {
        serialNumber: randomSerial(),
        subject: `CN=${commonName.kind === 'dns' ? commonName.ascii : commonName.ip}`,
        issuer: caCert.subject,
        notBefore,
        notAfter: new Date(notBefore.getTime() + validityDays * DAY_MS),
        signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
        publicKey: keys.publicKey,
        signingKey: caKey,
        extensions: [
          new BasicConstraintsExtension(false, undefined, true),
          new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
          new ExtendedKeyUsageExtension([ExtendedKeyUsage.serverAuth], true),
          new SubjectAlternativeNameExtension(
            names.map((name) =>
              name.kind === 'dns'
                ? { type: 'dns' as const, value: name.ascii }
                : { type: 'ip' as const, value: name.ip },
            ),
            true,
          ),
        ],
      },
      webcrypto,
    );
    return {
      keyPem: privateKeyPem(
        await webcrypto.subtle.exportKey('pkcs8', keys.privateKey),
      ),
      certPem: cert.toString('pem'),
      expiresAt: cert.notAfter.toISOString(),
    };
  } catch (cause) {
    throw generationError(cause);
  }
}
