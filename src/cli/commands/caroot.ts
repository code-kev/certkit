import { type CommandDef, defineCommand } from 'citty';
import { jsonOutput, loadApi } from '../options.js';

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

export const carootCommand: CommandDef<Args> = defineCommand({
  meta: { name: 'caroot', description: 'Print the CA directory path' },
  args,
  async run({ args }) {
    const { caDir } = await loadApi();
    const path = caDir();
    if (jsonOutput || args.json) {
      console.log(JSON.stringify({ schemaVersion: 1, caDir: path }));
    } else {
      console.log(path);
    }
  },
});
