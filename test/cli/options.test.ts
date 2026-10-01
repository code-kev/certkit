import { type ArgsDef, parseArgs as parseCittyArgs } from 'citty';
import pc from 'picocolors';
import { afterEach, describe, expect, it } from 'vitest';
import { createCommand } from '../../src/cli/commands/create.js';
import { installCommand } from '../../src/cli/commands/install.js';
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

  it('validates install flags from the declared command schema', () => {
    expect(
      options.validateOptions(
        ['--dryrun'],
        installCommand.args as Record<string, { type: string }>,
      ),
    ).toContain("Unknown option '--dryrun'");
  });

  it('still detects unknown flags after Citty boolean value syntax', () => {
    expect(
      options.validateOptions(
        ['--json=true', '--dryrun'],
        installCommand.args as Record<string, { type: string }>,
      ),
    ).toContain("Unknown option '--dryrun'");
  });

  it('accepts declared short aliases and the positional delimiter', async () => {
    expect(
      options.validateOptions(
        ['-o', 'dist', '--', '--name'],
        createCommand.args as Record<string, { type: string }>,
      ),
    ).toBeUndefined();
  });

  it.each([
    [['--output', '-private'], 'output', '-private'],
    [['-o', '-private'], 'output', '-private'],
    [['--validity-days', '-1'], 'validityDays', '-1'],
  ])(
    'matches Citty string values that begin with -: %s',
    (args, key, value) => {
      const definitions = createCommand.args as ArgsDef;
      expect(parseCittyArgs(args, definitions)[key]).toBe(value);
      expect(options.validateOptions(args, definitions)).toBeUndefined();
    },
  );

  it('checks for unknown options after a leading-dash string value', () => {
    expect(
      options.validateOptions(
        ['--output', '-private', '--unknown'],
        createCommand.args as ArgsDef,
      ),
    ).toContain("Unknown option '--unknown'");
  });
});
