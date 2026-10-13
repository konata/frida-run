// SPDX-License-Identifier: GPL-3.0-only
export async function execute(command, { timeout = 30_000, stdout = "pipe" } = {}) {
  const child = Bun.spawn(command, { stdout, stderr: "pipe", timeout });
  const [code, output, error] = await Promise.all([
    child.exited,
    stdout === "pipe" ? new Response(child.stdout).text() : "",
    new Response(child.stderr).text(),
  ]);
  if (child.signalCode) throw new Error(`${command[0]} terminated (${child.signalCode}); check connectivity or root authorization.`);
  return { code, output: output.trim(), error: error.trim() };
}

export function checked({ code, output, error }, operation) {
  if (code !== 0) throw new Error(`${operation} failed (${code}): ${error || output || "no diagnostic output"}`);
  return output;
}

export const quote = (text) => `'${text.replaceAll("'", "'\\''")}'`;
