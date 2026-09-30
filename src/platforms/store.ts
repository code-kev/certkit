import type { Environment } from './detect.js';

export interface StoreAdapter {
  id: 'macos-keychain' | 'windows-root' | 'linux-system' | 'nss';
  inspectInstalled(
    caCertPem: string,
    target: string,
    mechanism?: string,
  ): Promise<'present' | 'absent' | 'inconclusive'>;
  checkTrust(
    caCertPem: string,
    env: Environment,
  ): Promise<
    Array<{
      state: 'trusted' | 'untrusted' | 'unknown' | 'not-detected';
      target?: string;
      detail?: string;
    }>
  >;
  install(
    caCertPath: string,
    target: string,
    mechanism?: string,
  ): Promise<{ state: 'verified' | 'inconclusive'; detail?: string }>;
  uninstall(
    caCertPem: string,
    target: string,
    mechanism?: string,
  ): Promise<void>;
}
