import { describe, expect, test } from "bun:test";
import { binary, deploy, halt, status } from "../src/server.js";

function device({ running = null, uploaded = "17.23.3", lock = false, failed = null, disappeared = false } = {}) {
  const scripts = [];
  let locked = lock;
  return {
    serial: "emulator-5554", scripts,
    async shell(script) {
      scripts.push(script);
      if (failed === "upload" && script.startsWith("chmod")) throw new Error("chmod failed");
      return "";
    },
    async command(...arguments_) {
      scripts.push(arguments_);
      if (failed === "push") throw new Error("push failed");
      return "";
    },
    async root(script) {
      scripts.push(script);
      if (script.startsWith("mkdir")) {
        if (locked) throw new Error("File exists: .lock");
        locked = true;
      } else if (script.startsWith("rmdir")) locked = false;
      else if (script.includes("kill -TERM")) running = null;
      else if (script.includes("for process")) return running ? "123" : "";
      else if (script.endsWith("--version")) return script.startsWith("/proc/") ? running : uploaded;
      else if (script.endsWith("--daemonize")) {
        if (failed === "start") throw new Error("Unable to start: Address already in use");
        running = disappeared ? null : uploaded;
      }
      return "";
    },
  };
}

const release = { version: "17.23.3", filename: "/cache/server" };
const quiet = { echo() {} };

describe("server status", () => {
  test("reports only a process matching the managed executable", async () => {
    const selected = device({ running: "17.23.3" });
    expect(await status(selected)).toEqual({ pids: ["123"], version: "17.23.3" });
    expect(selected.scripts[0]).toContain("readlink");
    expect(selected.scripts[0]).toContain(`[ "$executable" = '${binary}' ] || continue`);
    expect(selected.scripts[1]).toBe("/proc/123/exe --version");
  });
  test("does not run a binary when the service is absent", async () => {
    const selected = device();
    expect(await status(selected)).toEqual({ pids: [], version: null });
    expect(selected.scripts.length).toBe(1);
  });
});

describe("deployment", () => {
  test("uploads, verifies, replaces and daemonizes", async () => {
    const selected = device();
    const messages = [];
    expect(await deploy(selected, release, { echo: (text) => messages.push(text) })).toEqual({ pids: ["123"], version: "17.23.3" });
    const push = selected.scripts.find((script) => Array.isArray(script));
    expect(push.slice(0, 2)).toEqual(["push", "/cache/server"]);
    expect(push[2]).toMatch(/^\/data\/local\/tmp\/frida-run\/\.server-/);
    expect(selected.scripts.some((script) => typeof script === "string" && script.includes("--daemonize"))).toBe(true);
    expect(messages).toHaveLength(1);
    expect(selected.scripts.at(-1)).toContain("rmdir");
  });
  test("matching version is not restarted", async () => {
    const selected = device({ running: "17.23.3" });
    const messages = [];
    await deploy(selected, release, { echo: (text) => messages.push(text) });
    expect(selected.scripts.every((script) => typeof script === "string")).toBe(true);
    expect(selected.scripts.join("\n")).not.toContain("kill -TERM");
    expect(messages[0]).toContain("already running");
  });
  test.each([false, true])("replaces an older service or forces a matching service (%s)", async (force) => {
    const selected = device({ running: force ? "17.23.3" : "16.0.0" });
    await deploy(selected, release, { ...quiet, force });
    const scripts = selected.scripts.filter((script) => typeof script === "string");
    const validation = scripts.findIndex((script) => script.includes(".server-") && script.endsWith("--version"));
    const termination = scripts.findIndex((script) => script.includes("kill -TERM"));
    const replacement = scripts.findIndex((script) => script.startsWith("mv"));
    const startup = scripts.findIndex((script) => script.endsWith("--daemonize"));
    expect(validation).toBeLessThan(termination);
    expect(termination).toBeLessThan(replacement);
    expect(replacement).toBeLessThan(startup);
    expect(scripts.join("\n")).not.toContain("killall");
  });
  test("wrong uploaded version leaves the old server running", async () => {
    const selected = device({ running: "16.0.0", uploaded: "17.0.0" });
    await expect(deploy(selected, release, quiet)).rejects.toThrow("version mismatch");
    expect((await status(selected)).version).toBe("16.0.0");
    expect(selected.scripts.join("\n")).not.toContain("kill -TERM");
    expect(selected.scripts.some((script) => typeof script === "string" && script.startsWith("rm -f"))).toBe(true);
  });
  test.each(["push", "upload", "start"])("propagates %s failure and releases its lock", async (failed) => {
    const selected = device({ failed });
    const messages = [];
    await expect(deploy(selected, release, { echo: (text) => messages.push(text) })).rejects.toThrow();
    expect(messages).toHaveLength(0);
    expect(selected.scripts.at(-1)).toContain("rmdir");
  });
  test("daemon disappearance is not reported as success", async () => {
    await expect(deploy(device({ disappeared: true }), release, quiet)).rejects.toThrow("exited after startup");
  });
  test("lock contention does not release another operation's lock", async () => {
    const selected = device({ lock: true });
    await expect(deploy(selected, release, quiet)).rejects.toThrow(".lock");
    expect(selected.scripts.join("\n")).not.toContain("rmdir");
    expect(selected.scripts.every((script) => typeof script === "string")).toBe(true);
  });
});

describe("stop", () => {
  test("stops only the managed service and waits for disappearance", async () => {
    const selected = device({ running: "17.23.3" });
    expect(await halt(selected)).toBe(true);
    expect(await status(selected)).toEqual({ pids: [], version: null });
    const script = selected.scripts.find((script) => script.includes("kill -TERM"));
    expect(script).toContain(`[ "$executable" = '${binary}' ] || continue`);
    expect(script).not.toContain("killall");
  });
  test("absent service is a successful no-op", async () => {
    const selected = device();
    expect(await halt(selected)).toBe(false);
    expect(selected.scripts.join("\n")).not.toContain("kill -TERM");
  });
});

test("all generated remote scripts have valid POSIX shell syntax", async () => {
  const selected = device({ running: "16.0.0" });
  await deploy(selected, release, quiet);
  await halt(selected);
  for (const script of selected.scripts.filter((script) => typeof script === "string")) {
    const child = Bun.spawn(["sh", "-n"], { stdin: "pipe", stdout: "pipe", stderr: "pipe" });
    child.stdin.write(script);
    child.stdin.end();
    const error = await new Response(child.stderr).text();
    expect(await child.exited).toBe(0);
    expect(error).toBe("");
  }
});
