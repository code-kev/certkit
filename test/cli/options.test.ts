import pc from 'picocolors';
import { afterEach, describe, expect, it } from 'vitest';
import * as options from '../../src/cli/options.js';

afterEach(() => {
  options.setGlobalOptions({});
});

describe('CLI global options', () => {
  it('defaults to human output', () => {
    expect(options.jsonOutput).toBe(false);
  });

  it('toggles JSON output via the global option', () => {
    options.setGlobalOptions({ json: true });
    expect(options.jsonOutput).toBe(true);
    options.setGlobalOptions({ json: false });
    expect(options.jsonOutput).toBe(false);
    options.setGlobalOptions({});
    expect(options.jsonOutput).toBe(false);
  });

  it('gates colors on terminal support and the global color flag', () => {
    options.setGlobalOptions({ color: false });
    expect(options.colors().isColorSupported).toBe(false);
    expect(options.colors(true).isColorSupported).toBe(false);

    options.setGlobalOptions({ color: true });
    expect(options.colors().isColorSupported).toBe(pc.isColorSupported);

    options.setGlobalOptions({});
    expect(options.colors().isColorSupported).toBe(pc.isColorSupported);
    expect(options.colors(false).isColorSupported).toBe(false);
  });

  it('exposes the package version', async () => {
    expect(options.cliVersion).toBe(
      (await import('../../package.json', { with: { type: 'json' } })).default
        .version,
    );
  });

  it('loads the public API lazily', async () => {
    const api = await options.loadApi();

    expect(typeof api.caDir).toBe('function');
    expect(typeof api.status).toBe('function');
  });
});
