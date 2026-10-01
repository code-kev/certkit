#!/usr/bin/env node
import '../reflect-metadata.js';
import { type ArgsDef, defineCommand, renderUsage, runMain } from 'citty';
import { carootCommand } from './commands/caroot.js';
import { createCommand } from './commands/create.js';
import { installCommand } from './commands/install.js';
import { statusCommand } from './commands/status.js';
import { uninstallCommand } from './commands/uninstall.js';
import { cliVersion, setGlobalOptions, validateOptions } from './options.js';

const commands = {
  caroot: carootCommand,
  create: createCommand,
  install: installCommand,
  status: statusCommand,
  uninstall: uninstallCommand,
};
const globalArgs: ArgsDef = {
  json: { type: 'boolean', description: 'Print JSON' },
  color: {
    type: 'boolean',
    default: true,
    negativeDescription: 'Disable color',
  },
};
const main = defineCommand({
  meta: {
    name: 'certkit',
    version: cliVersion,
    description: 'Trusted local HTTPS development certificates',
  },
  args: globalArgs,
  setup({ args }) {
    setGlobalOptions({
      json: args['json'] === true,
      color: args['color'] !== false,
    });
  },
  subCommands: commands,
});

const rawArgs = process.argv.slice(2);
const commandName = rawArgs.find((arg) => !arg.startsWith('-'));
const commandIndex = rawArgs.indexOf(commandName ?? '');
if (commandName && !Object.hasOwn(commands, commandName)) {
  process.stderr.write(
    `${await renderUsage(main)}\nUnknown command: ${commandName}\n`,
  );
  process.exitCode = 2;
} else {
  const helpRequested = rawArgs.some((arg) => arg === '--help' || arg === '-h');
  const versionRequested =
    rawArgs.length === 1 && (rawArgs[0] === '--version' || rawArgs[0] === '-v');
  const childArgs = commandName
    ? (commands[commandName as keyof typeof commands].args as ArgsDef)
    : {};
  const optionError =
    helpRequested || versionRequested
      ? undefined
      : commandIndex < 0
        ? validateOptions(rawArgs, globalArgs)
        : (validateOptions(rawArgs.slice(0, commandIndex), globalArgs) ??
          validateOptions(rawArgs.slice(commandIndex + 1), {
            ...globalArgs,
            ...childArgs,
          }));
  if (optionError) {
    const flagArgs = rawArgs.slice(
      0,
      rawArgs.indexOf('--') < 0 ? undefined : rawArgs.indexOf('--'),
    );
    const json = flagArgs.some(
      (arg) => arg === '--json' || /^--json=(?!false$)/.test(arg),
    );
    if (json) {
      console.log(
        JSON.stringify({
          schemaVersion: 1,
          error: { code: 'INVALID_OPTIONS', message: optionError },
        }),
      );
    } else {
      console.error(`certkit: INVALID_OPTIONS: ${optionError}`);
    }
    process.exitCode = 2;
  } else {
    await runMain(main, { rawArgs });
  }
}
