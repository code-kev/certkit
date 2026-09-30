import type { Plugin } from 'vite';
import type { StatusReport } from '../index.js';

const DEFAULT_HOSTS = ['localhost', '127.0.0.1', '::1'];

export function certkit(options: { hosts?: string[] } = {}): Plugin {
  const hosts = options.hosts ?? DEFAULT_HOSTS;
  return {
    name: 'certkit',
    apply: 'serve',
    async config(config) {
      if (!config.server?.https || typeof config.server.https !== 'object')
        return;

      const { certificateFor, status } = await import('../index.js');
      const stores = (await status()).stores.filter(({ store }) =>
        process.platform === 'darwin'
          ? store === 'macos-keychain' || store === 'nss'
          : process.platform === 'win32'
            ? store === 'windows-root' || store === 'nss'
            : store === 'nss',
      );
      const detected = stores.filter(({ state }) => state !== 'not-detected');
      const untrusted = detected.filter(({ state }) => state === 'untrusted');
      const name = ({ store, target }: StatusReport['stores'][number]) =>
        `${store}${target ? ` (${target})` : ''}`;

      if (detected.length > 0 && untrusted.length === detected.length)
        throw new Error(
          `All detected browser certificate targets are untrusted (${untrusted.map(name).join(', ')}). Run \`certkit install\` and restart Vite.`,
        );

      if (detected.length === 0)
        console.warn(
          'certkit: no browser trust target was detected; certificate trust is uncertain.',
        );
      for (const target of stores.filter(
        ({ state }) =>
          state === 'untrusted' ||
          state === 'unknown' ||
          state === 'not-detected',
      ))
        console.warn(
          `certkit: ${name(target)} is ${target.state}; browser trust is unverified.`,
        );

      const certificate = await certificateFor(hosts);
      return {
        server: { https: { key: certificate.key, cert: certificate.cert } },
      };
    },
  };
}
