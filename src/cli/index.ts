#!/usr/bin/env node
import '../reflect-metadata.js';
import { defineCommand, renderUsage, runMain } from 'citty';
import { carootCommand } from './commands/caroot.js';
import { createCommand } from './commands/create.js';
import { statusCommand } from './commands/status.js';
import { cliVersion, setGlobalOptions } from './options.js';

const commands = {
  caroot: carootCommand,
  create: createCommand,
  status: statusCommand,
};
const main = defineCommand({
  meta: {
    name: 'certkit',
    version: cliVersion,
    description: 'Trusted local HTTPS development certificates',
  },
  args: {
    json: { type: 'boolean', description: 'Print JSON' },
    color: {
      type: 'boolean',
      default: true,
      negativeDescription: 'Disable color',
    },
  },
  setup({ args }) {
    setGlobalOptions({ json: args.json ?? false, color: args.color });
  },
  subCommands: commands,
});

const rawArgs = process.argv.slice(2);
const commandName = rawArgs.find((arg) => !arg.startsWith('-'));
if (commandName && !Object.hasOwn(commands, commandName)) {
  process.stderr.write(
    `${await renderUsage(main)}\nUnknown command: ${commandName}\n`,
  );
  process.exitCode = 2;
} else {
  await runMain(main, { rawArgs });
}
