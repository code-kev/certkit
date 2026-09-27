import { type CommandDef, defineCommand } from 'citty';
import { cliVersion, colors, jsonOutput, loadApi } from '../options.js';

type Args = {
  json: { type: 'boolean'; description: 'Print JSON' };
  color: {
    type: 'boolean';
    default: true;
    negativeDescription: 'Disable color';
  };
};
const args: Args = {
  json: { type: 'boolean', description: 'Print JSON' },
  color: {
    type: 'boolean',
    default: true,
    negativeDescription: 'Disable color',
  },
};

export const statusCommand: CommandDef<Args> = defineCommand({
  meta: { name: 'status', description: 'Report CA trust status' },
  args,
  async run({ args }) {
    try {
      const { status } = await loadApi();
      const report = await status();
      if (jsonOutput || args.json) {
        console.log(
          JSON.stringify({ schemaVersion: 1, version: cliVersion, ...report }),
        );
      } else {
        const pc = colors(args.color);
        console.log(`CA directory: ${report.caDir}`);
        console.log(
          report.ca
            ? `CA: ${report.ca.subject} (expires ${report.ca.expiresAt})`
            : 'CA: not initialized',
        );
        console.log('Stores:');
        for (const store of report.stores) {
          const state =
            store.state === 'trusted'
              ? pc.green(store.state)
              : store.state === 'untrusted'
                ? pc.red(store.state)
                : pc.yellow(store.state);
          console.log(
            `  ${store.store}${store.target ? ` (${store.target})` : ''}: ${state}${store.detail ? ` — ${store.detail}` : ''}`,
          );
        }
      }
      if (report.stores.some((store) => store.state === 'untrusted'))
        process.exitCode = 1;
    } catch (error) {
      if (error instanceof Error && error.name === 'CertkitError') {
        const code = (error as Error & { code?: string }).code ?? 'CLI_ERROR';
        if (jsonOutput || args.json) {
          console.log(
            JSON.stringify({
              schemaVersion: 1,
              version: cliVersion,
              error: {
                code,
                message: error.message,
              },
            }),
          );
        } else {
          console.error(`certkit: ${code}: ${error.message}`);
        }
      } else {
        console.error('certkit: unexpected error');
      }
      process.exitCode = 1;
    }
  },
});
