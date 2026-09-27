import './reflect-metadata.js';
import {
  type CertificateBundle,
  type CertificateOptions,
  caDir,
  certificateFor as certificateForCore,
} from './core/certificate.js';
import { createWindowsFsGuard } from './platforms/fsguard.js';

export type { ErrorCode } from './core/errors.js';
export { CertkitError } from './core/errors.js';
export type { CertificateBundle, CertificateOptions };
export { caDir };

export function certificateFor(
  names: string[],
  options?: CertificateOptions,
): Promise<CertificateBundle> {
  return certificateForCore(
    names,
    options,
    process.platform === 'win32' ? { fsGuard: createWindowsFsGuard() } : {},
  );
}
