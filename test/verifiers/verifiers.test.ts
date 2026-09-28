import 'reflect-metadata';
import { spawnSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ExtendedKeyUsage,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  X509Certificate as PeculiarCertificate,
  SubjectAlternativeNameExtension,
} from '@peculiar/x509';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mintCa, mintLeaf } from '../../src/core/certgen.js';
import { certificateFor } from '../../src/core/certificate.js';
import { resolveNssCertutil } from '../../src/platforms/run.js';
import {
  type CorpusCase,
  corpus,
  expectedExtendedKeyUsage,
  expectedKeyUsage,
  notBeforeSkewMs,
} from './corpus.js';

const DAY_MS = 86_400_000;

function binaryAvailable(binary: string): boolean {
  const result = spawnSync(binary, [], { encoding: 'utf8' });
  return !(result.error && result.error.code === 'ENOENT');
}

const openssl = binaryAvailable('openssl');
// Reuse the project's NSS resolver so this oracle never runs the Windows
// System32 certutil, which is a different tool.
const certutil = await resolveNssCertutil();
const security = process.platform === 'darwin' && binaryAvailable('security');

interface MintedCase {
  readonly case: CorpusCase;
  readonly caPath: string;
  readonly leafPath: string;
  readonly leafPem: string;
}

let root = '';
const minted: MintedCase[] = [];

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), 'certkit-verifiers-'));
  for (const testCase of corpus) {
    const caDir = join(root, testCase.id, 'ca');
    const bundle = await certificateFor(testCase.names, {
      caDir,
      validityDays: testCase.validityDays,
    });
    const caPath = join(root, testCase.id, 'ca.pem');
    const leafPath = join(root, testCase.id, 'leaf.pem');
    writeFileSync(caPath, bundle.caCert);
    writeFileSync(leafPath, bundle.cert);
    minted.push({
      case: testCase,
      caPath,
      leafPath,
      leafPem: bundle.cert,
    });
  }
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

const cases = (): Array<[string, CorpusCase]> =>
  corpus.map((testCase) => [testCase.id, testCase]);

function entryFor(testCase: CorpusCase): MintedCase {
  const entry = minted.find((candidate) => candidate.case.id === testCase.id);
  if (!entry) throw new Error(`no minted entry for ${testCase.id}`);
  return entry;
}

function opensslText(leafPath: string): string {
  const result = spawnSync(
    'openssl',
    ['x509', '-in', leafPath, '-noout', '-text'],
    {
      encoding: 'utf8',
    },
  );
  expect(result.status, result.stderr).toBe(0);
  return result.stdout;
}

function opensslSanLine(text: string): string {
  const match = /X509v3 Subject Alternative Name:[\s\S]*?\n\s+(.*)\n/.exec(
    text,
  );
  return match?.[1]?.trim() ?? '';
}

describe('golden corpus invariants (no oracle required)', () => {
  it.each(cases())(
    '%s mints the golden SAN, extensions, and backdated validity',
    (_id, testCase) => {
      const entry = entryFor(testCase);
      const parsed = new PeculiarCertificate(entry.leafPem);
      const actualSan = (
        parsed.getExtension(SubjectAlternativeNameExtension)?.names.toJSON() ??
        []
      )
        .map((name) =>
          name.type === 'ip'
            ? { type: 'ip' as const, value: name.value.toLowerCase() }
            : { type: 'dns' as const, value: name.value.toLowerCase() },
        )
        .sort((a, b) =>
          `${a.type}:${a.value}`.localeCompare(`${b.type}:${b.value}`),
        );
      expect(actualSan).toEqual(
        [...entry.case.san].sort((a, b) =>
          `${a.type}:${a.value}`.localeCompare(`${b.type}:${b.value}`),
        ),
      );

      expect(parsed.getExtension(KeyUsagesExtension)?.usages).toBe(
        KeyUsageFlags.digitalSignature,
      );
      expect(parsed.getExtension(ExtendedKeyUsageExtension)?.usages).toContain(
        ExtendedKeyUsage.serverAuth,
      );

      const now = Date.now();
      expect(parsed.notBefore.getTime()).toBeGreaterThanOrEqual(
        now - notBeforeSkewMs - 5_000,
      );
      expect(parsed.notBefore.getTime()).toBeLessThanOrEqual(
        now - notBeforeSkewMs + 5_000,
      );
      expect(parsed.notAfter.getTime() - parsed.notBefore.getTime()).toBe(
        entry.case.validityDays * DAY_MS,
      );
    },
  );

  it('never reuses a serial across distinct mints', async () => {
    const first = await mintCa('serial-entropy');
    const second = await mintCa('serial-entropy');
    const leafA = await mintLeaf(first, [{ kind: 'dns', ascii: 'a.test' }], 30);
    const leafB = await mintLeaf(first, [{ kind: 'dns', ascii: 'b.test' }], 30);
    const serials = [
      first.serial,
      second.serial,
      new X509Certificate(leafA.certPem).serialNumber,
      new X509Certificate(leafB.certPem).serialNumber,
    ].map((serial) => serial.toLowerCase());
    expect(new Set(serials).size).toBe(serials.length);
  });

  it('enforces the 825-day boundary at parse time', async () => {
    await expect(
      certificateFor(['localhost'], {
        caDir: join(root, 'over-boundary', 'ca'),
        validityDays: 826,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_OPTIONS' });
  });
});

describe('openssl oracle', () => {
  beforeAll(() => {
    if (!openssl)
      console.warn(
        'verifier oracle skipped (openssl): certificate chains and fields are unverified',
      );
  });

  it.skipIf(!openssl).each(cases())(
    '%s verifies against its CA and reports golden fields',
    (_id, testCase) => {
      const entry = entryFor(testCase);
      const verified = spawnSync(
        'openssl',
        ['verify', '-CAfile', entry.caPath, entry.leafPath],
        {
          encoding: 'utf8',
        },
      );
      expect(verified.status, verified.stderr).toBe(0);
      expect(verified.stdout).toContain(': OK');

      const flag =
        entry.case.verifyHost.kind === 'ip' ? '-verify_ip' : '-verify_hostname';
      const named = spawnSync(
        'openssl',
        [
          'verify',
          '-CAfile',
          entry.caPath,
          flag,
          entry.case.verifyHost.value,
          entry.leafPath,
        ],
        { encoding: 'utf8' },
      );
      expect(named.status, named.stderr).toBe(0);

      const text = opensslText(entry.leafPath);
      expect(opensslSanLine(text)).toBe(entry.case.opensslSan);
      expect(text).toMatch(
        new RegExp(`X509v3 Key Usage: critical[\\s\\S]*?${expectedKeyUsage}`),
      );
      expect(text).toMatch(
        new RegExp(
          `X509v3 Extended Key Usage: critical[\\s\\S]*?${expectedExtendedKeyUsage}`,
        ),
      );
      expect(/^\s*Subject: (.*)$/m.exec(text)?.[1]?.trim()).toBe(
        `CN=${entry.case.commonName}`,
      );
    },
  );
});

describe('NSS certutil oracle', () => {
  beforeAll(() => {
    if (!certutil)
      console.warn(
        'verifier oracle skipped (certutil): NSS certification-path validation is unverified',
      );
  });

  it.skipIf(!certutil).each(cases())(
    '%s validates in a fresh NSS database',
    (_id, testCase) => {
      const entry = entryFor(testCase);
      const binary = certutil as string;
      const sql = `sql:${join(root, entry.case.id, 'nssdb')}`;
      mkdirSync(join(root, entry.case.id, 'nssdb'), { recursive: true });
      const runCertutil = (args: string[]) =>
        spawnSync(binary, args, { encoding: 'utf8' });

      const initialised = runCertutil(['-N', '-d', sql, '--empty-password']);
      expect(initialised.status, initialised.stderr).toBe(0);
      const addedCa = runCertutil([
        '-A',
        '-n',
        'ca',
        '-t',
        'C,,',
        '-d',
        sql,
        '-i',
        entry.caPath,
      ]);
      expect(addedCa.status, addedCa.stderr).toBe(0);
      const addedLeaf = runCertutil([
        '-A',
        '-n',
        'leaf',
        '-t',
        ',,',
        '-d',
        sql,
        '-i',
        entry.leafPath,
      ]);
      expect(addedLeaf.status, addedLeaf.stderr).toBe(0);

      const verified = runCertutil(['-V', '-n', 'leaf', '-u', 'V', '-d', sql]);
      expect(verified.status, `${verified.stdout}\n${verified.stderr}`).toBe(0);
      expect(`${verified.stdout}${verified.stderr}`).toMatch(
        /certificate is valid/i,
      );
    },
  );
});

describe('macOS security oracle', () => {
  beforeAll(() => {
    if (process.platform !== 'darwin')
      console.warn('verifier oracle skipped (security): macOS-only verifier');
    else if (!security)
      console.warn(
        'verifier oracle skipped (security): security is not available on PATH',
      );
  });

  it.skipIf(!security).each(cases())(
    '%s is accepted by the default SSL policy for its host',
    (_id, testCase) => {
      const entry = entryFor(testCase);
      const verified = spawnSync(
        'security',
        [
          'verify-cert',
          '-c',
          entry.leafPath,
          '-r',
          entry.caPath,
          '-p',
          'ssl',
          '-n',
          entry.case.verifyHost.value,
          '-L',
        ],
        { encoding: 'utf8' },
      );
      expect(verified.status, `${verified.stdout}\n${verified.stderr}`).toBe(0);
      expect(`${verified.stdout}${verified.stderr}`).toMatch(
        /verification successful/i,
      );
    },
  );
});
