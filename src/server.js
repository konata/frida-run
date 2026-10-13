// SPDX-License-Identifier: GPL-3.0-only
import { quote } from "./process.js";

export const directory = "/data/local/tmp/frida-run";
export const binary = `${directory}/frida-server`;

const processes = `for process in /proc/[0-9]*; do
  executable=$(readlink "$process/exe" 2>/dev/null) || continue
  [ "$executable" = ${quote(binary)} ] || continue
  printf '%s\\n' "\${process##*/}"
done`;

export async function status(device) {
  const output = await device.root(processes);
  const pids = output ? output.split("\n") : [];
  const version = pids.length ? await device.root(`/proc/${pids[0]}/exe --version`) : null;
  return { pids, version };
}

async function stop(device) {
  await device.root(`for process in /proc/[0-9]*; do
  executable=$(readlink "$process/exe" 2>/dev/null) || continue
  [ "$executable" = ${quote(binary)} ] || continue
  kill -TERM "\${process##*/}" || exit $?
done`);
  for (let attempt = 0; attempt < 25; attempt++) {
    const output = await device.root(processes);
    if (!output) return;
    await Bun.sleep(200);
  }
  throw new Error("frida-server did not stop within five seconds; no replacement was installed.");
}

async function exclusive(device, operation) {
  await device.shell(`mkdir -p ${quote(directory)}`);
  const lock = `${directory}/.lock`;
  await device.root(`mkdir ${quote(lock)}`);
  try {
    return await operation();
  } finally {
    await device.root(`rmdir ${quote(lock)}`);
  }
}

export async function halt(device) {
  return exclusive(device, async () => {
    const { pids } = await status(device);
    if (pids.length) await stop(device);
    return pids.length > 0;
  });
}

export async function deploy(device, release, { force = false, echo = console.log } = {}) {
  return exclusive(device, async () => {
    const current = await status(device);
    if (!force && current.pids.length === 1 && current.version === release.version) {
      echo(`frida-server ${current.version} is already running on ${device.serial} (PID ${current.pids[0]}).`);
      return current;
    }
    const staged = `${directory}/.server-${crypto.randomUUID()}`;
    try {
      await device.command("push", release.filename, staged);
      await device.shell(`chmod 0755 ${quote(staged)}`);
      const version = await device.root(`${quote(staged)} --version`);
      if (version !== release.version) throw new Error(`Uploaded server version mismatch: expected ${release.version}, received ${version}.`);
      if (current.pids.length) await stop(device);
      await device.root(`mv -f ${quote(staged)} ${quote(binary)}`);
      await device.root(`${quote(binary)} --daemonize`);
      const running = await status(device);
      if (running.pids.length !== 1 || running.version !== release.version) throw new Error("frida-server exited after startup or its identity could not be verified.");
      echo(`frida-server ${running.version} is running on ${device.serial} (PID ${running.pids[0]}).`);
      return running;
    } finally {
      await device.shell(`rm -f ${quote(staged)}`);
    }
  });
}
