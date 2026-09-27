import { execFileSync, spawnSync } from 'node:child_process';
import { createHash, createPrivateKey } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { mintCa, mintLeaf } from '../../src/core/certgen.js';
import type { ValidName } from '../../src/core/validate.js';

const names: ValidName[] = [
  { kind: 'dns', ascii: 'localhost' },
  { kind: 'ip', ip: '127.0.0.1' },
];
const opensslAvailable = spawnSync('openssl', ['version']).status === 0;
const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

describe('certificate generation', () => {
  it.skipIf(!opensslAvailable)(
    'mints a CA and leaf accepted by OpenSSL with required extensions',
    async () => {
      const caStartedAt = Date.now();
      const caMaterial = await mintCa('alice-1');
      const leafStartedAt = Date.now();
      const leafMaterial = await mintLeaf(caMaterial, names, 825);
      const {
        BasicConstraintsExtension,
        ExtendedKeyUsage,
        ExtendedKeyUsageExtension,
        KeyUsageFlags,
        KeyUsagesExtension,
        SubjectAlternativeNameExtension,
        X509Certificate,
      } = await import('@peculiar/x509');
      const dir = mkdtempSync(join(tmpdir(), 'certkit-certgen-'));
      tempDirs.push(dir);
      const caPath = join(dir, 'ca.pem');
      const leafPath = join(dir, 'leaf.pem');
      writeFileSync(caPath, caMaterial.certPem);
      writeFileSync(leafPath, leafMaterial.certPem);

      const verified = spawnSync(
        'openssl',
        ['verify', '-CAfile', caPath, leafPath],
        { encoding: 'utf8' },
      );
      expect(verified.status, verified.stderr).toBe(0);
      expect(verified.stdout).toContain(': OK');

      const caText = execFileSync(
        'openssl',
        ['x509', '-in', caPath, '-noout', '-text'],
        { encoding: 'utf8' },
      );
      expect(caText).toMatch(/X509v3 Key Usage:[\s\S]*Digital Signature/);

      const ca = new X509Certificate(caMaterial.certPem);
      const leaf = new X509Certificate(leafMaterial.certPem);
      expect(ca.subject).toContain('CN=certkit development CA');
      expect(ca.subject).toContain('OU=alice-1');
      expect(ca.notBefore.getTime()).toBeGreaterThanOrEqual(
        caStartedAt - 301_000,
      );
      expect(ca.notBefore.getTime()).toBeLessThanOrEqual(caStartedAt - 299_000);
      expect(ca.getExtension(BasicConstraintsExtension)?.ca).toBe(true);
      expect(ca.getExtension(KeyUsagesExtension)?.usages).toBe(
        KeyUsageFlags.digitalSignature |
          KeyUsageFlags.keyCertSign |
          KeyUsageFlags.cRLSign,
      );
      expect(ca.serialNumber).toBe(caMaterial.serial);
      expect(BigInt(`0x${caMaterial.serial}`)).toBeGreaterThanOrEqual(
        1n << 64n,
      );
      expect(caMaterial.subject).toBe(ca.subject);
      expect(caMaterial.expiresAt).toBe(ca.notAfter.toISOString());

      expect(
        leaf.getExtension(SubjectAlternativeNameExtension)?.names.toJSON(),
      ).toEqual([
        { type: 'dns', value: 'localhost' },
        { type: 'ip', value: '127.0.0.1' },
      ]);
      expect(leaf.getExtension(ExtendedKeyUsageExtension)?.usages).toContain(
        ExtendedKeyUsage.serverAuth,
      );
      expect(leaf.getExtension(KeyUsagesExtension)?.usages).toBe(
        KeyUsageFlags.digitalSignature,
      );
      expect(
        createPrivateKey(caMaterial.keyPem).asymmetricKeyDetails?.namedCurve,
      ).toBe('prime256v1');
      expect(
        createPrivateKey(leafMaterial.keyPem).asymmetricKeyDetails?.namedCurve,
      ).toBe('prime256v1');
      expect(leafMaterial.expiresAt).toBe(leaf.notAfter.toISOString());
      expect(leaf.notBefore.getTime()).toBeGreaterThanOrEqual(
        leafStartedAt - 301_000,
      );
      expect(leaf.notBefore.getTime()).toBeLessThanOrEqual(
        leafStartedAt - 299_000,
      );
      expect(leaf.notAfter.getTime() - leaf.notBefore.getTime()).toBe(
        825 * 86_400_000,
      );

      expect((await mintCa('alice-1')).serial).not.toBe(caMaterial.serial);
    },
  );

  it('hashes a non-conforming user marker before placing it in the CA subject', async () => {
    const marker = 'alice,OU=attacker';
    const hashedMarker = createHash('sha256')
      .update(marker)
      .digest('hex')
      .slice(0, 12);
    const { certPem } = await mintCa(marker);
    const { X509Certificate } = await import('@peculiar/x509');
    const ca = new X509Certificate(certPem);

    expect(ca.subject).toContain(`OU=${hashedMarker}`);
    expect(ca.subject).not.toContain('OU=attacker');
  });

  it('rejects leaf validity beyond 825 days', async () => {
    await expect(
      mintLeaf(await mintCa('alice'), names, 826),
    ).rejects.toMatchObject({
      code: 'INVALID_OPTIONS',
    });
  });

  it('rejects a leaf with no names because its SAN would be empty', async () => {
    await expect(mintLeaf(await mintCa('alice'), [], 30)).rejects.toMatchObject(
      {
        code: 'INVALID_NAME',
      },
    );
  });
});
