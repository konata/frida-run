#!/usr/bin/env bun
// SPDX-License-Identifier: GPL-3.0-only
// Bun rewrite by konata (2026-10-13), based on AndroidTamer's GPLv3 frida-push.
import { join, dirname } from "node:path";
import { parseArgs } from "node:util";
import { Device, devices, select } from "./device.js";
import { checked, execute } from "./process.js";
import { release, version } from "./release.js";
import { deploy, halt, status } from "./server.js";
import metadata from "../package.json";

export const help = `frida-run — Download, deploy, and start frida-server on Android.

Usage: frida-run [run|status|stop] [options]

Commands:
  run                         Deploy and start (default); reuse a matching service
  status                      Inspect the service managed by frida-run
  stop                        Stop only the service managed by frida-run

Options:
  -d, --device <serial>        Select an ADB device (--device-name is also accepted)
      --frida-version <value> Use a specific version or explicitly request latest
  -f, --force                 Download again and redeploy, even if already running
  -h, --help                  Show this help
      --version               Show the frida-run version, not the server version

Examples:
  frida-run --frida-version 17.23.3
  frida-run --device emulator-5554 --frida-version latest
  frida-run status --device emulator-5554
  frida-run stop

Requires Bun >= 1.3, adb, xz, and a rooted Android device.
Without --frida-version, use the current project's npm frida package or frida CLI.
The server listens on Frida's default device-local address (127.0.0.1:27042).
Cache: ~/.cache/frida-run; device files: /data/local/tmp/frida-run.
A concurrent operation is rejected. If an interrupted operation leaves .lock,
remove that directory on the device only after confirming no operation is active.

Based on AndroidTamer/frida-push; rewritten by konata in 2026.
GPL-3.0-only; no warranty. See the included LICENSE for redistribution terms.`;

export function options(arguments_) {
  const { values, positionals } = parseArgs({
    args: arguments_,
    allowPositionals: true,
    options: {
      device: { type: "string", short: "d" },
      "device-name": { type: "string" },
      "frida-version": { type: "string" },
      force: { type: "boolean", short: "f" },
      help: { type: "boolean", short: "h" },
      version: { type: "boolean" },
    },
  });
  if (values.help || values.version) return values;
  for (const name of ["device", "device-name", "frida-version"]) {
    if (values[name] === "") throw new Error(`--${name} requires a nonempty value.`);
  }
  if (positionals.length > 1 || !["run", "status", "stop"].includes(positionals[0] ?? "run")) throw new Error("Expected run, status, or stop; use --help for usage.");
  if (values.device && values["device-name"] && values.device !== values["device-name"]) throw new Error("--device and --device-name select different devices.");
  const command = positionals[0] ?? "run";
  if (command !== "run" && (values.force || values["frida-version"])) throw new Error(`--force and --frida-version apply only to run, not ${command}.`);
  if (values["frida-version"] && values["frida-version"] !== "latest") version(values["frida-version"]);
  return { command, serial: values.device ?? values["device-name"], requested: values["frida-version"], force: values.force ?? false };
}

export async function client(requested, { cwd = process.cwd(), execute: command = execute } = {}) {
  if (requested) return requested === "latest" ? requested : version(requested);
  for (let directory = cwd; ; directory = dirname(directory)) {
    const manifest = Bun.file(join(directory, "node_modules/frida/package.json"));
    if (await manifest.exists()) return version((await manifest.json()).version);
    if (dirname(directory) === directory) break;
  }
  const executable = Bun.which("frida");
  if (executable) return version(checked(await command([executable, "--version"]), "Reading Frida client version"));
  throw new Error("No Frida client found. Install frida in your project or pass --frida-version <version|latest>; latest may not match your client.");
}

export async function main(arguments_ = process.argv.slice(2)) {
  const { command, serial, requested, force, help: showHelp, version: showVersion } = options(arguments_);
  if (showHelp) return console.log(help);
  if (showVersion) return console.log(metadata.version);
  if (!Bun.which("adb")) throw new Error("adb not found in PATH. Install Android SDK Platform Tools.");
  const connected = devices(checked(await execute(["adb", "devices", "-l"]), "Listing ADB devices"));
  const device = new Device(select(connected, serial));
  console.log(`Device: ${device.serial}`);
  const requestedVersion = command === "run" ? await client(requested) : null;
  await device.authorize();
  if (command === "stop") return console.log(await halt(device) ? "frida-server stopped." : "frida-server is not running.");
  if (command === "status") {
    const { pids, version } = await status(device);
    return console.log(pids.length ? `frida-server ${version} is running (PID ${pids.join(", ")}).` : "frida-server is not running.");
  }
  const architecture = await device.architecture();
  console.log(`Architecture: ${architecture}`);
  const server = await release(requestedVersion, architecture, { force });
  await deploy(device, server, { force });
}

if (import.meta.main) {
  try {
    await main();
  } catch (error) {
    console.error(`frida-run: ${error.message}`);
    process.exitCode = 1;
  }
}
