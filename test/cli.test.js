import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { client, options } from "../src/cli.js";
import { checked, execute, quote } from "../src/process.js";

const directories = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function workspace() {
  const directory = await mkdtemp(join(tmpdir(), "frida-run-cli-"));
  directories.push(directory);
  return directory;
}

function cli(arguments_, environment = {}) {
  return Bun.spawn([process.execPath, join(import.meta.dir, "../src/cli.js"), ...arguments_], {
    env: { ...process.env, ...environment }, stdout: "pipe", stderr: "pipe",
  });
}

async function output(child) {
  const [code, stdout, stderr] = await Promise.all([child.exited, new Response(child.stdout).text(), new Response(child.stderr).text()]);
  return { code, stdout, stderr };
}

describe("options", () => {
  test("defaults to run", () => {
    expect(options([])).toEqual({ command: "run", serial: undefined, requested: undefined, force: false });
  });
  test("accepts explicit commands and legacy device alias", () => {
    expect(options(["run", "--device-name", "emulator-5554", "-f", "--frida-version", "17.23.3"])).toEqual({ command: "run", serial: "emulator-5554", requested: "17.23.3", force: true });
    expect(options(["-d", "serial", "status"]).command).toBe("status");
    expect(options(["stop"]).command).toBe("stop");
    expect(options(["--frida-version=latest"]).requested).toBe("latest");
  });
  test.each([
    ["launch"], ["run", "stop"], ["--unknown"], ["-d"],
    ["--device="], ["--device-name="], ["--frida-version="],
    ["--frida-version", "../escape"], ["--device", "a", "--device-name", "b"],
    ["status", "--force"], ["stop", "--frida-version", "latest"],
  ])("rejects invalid arguments %j", (...arguments_) => {
    expect(() => options(arguments_)).toThrow();
  });
  test("help and tool version do not require device or server version", () => {
    expect(options(["-h"]).help).toBe(true);
    expect(options(["--version"]).version).toBe(true);
  });
});

describe("client version", () => {
  test("explicit versions bypass local client detection", async () => {
    expect(await client("17.23.3")).toBe("17.23.3");
    expect(await client("latest")).toBe("latest");
    await expect(client("broken")).rejects.toThrow();
  });
  test("reads npm frida from the current project and ancestors without loading native bindings", async () => {
    const directory = await workspace();
    await mkdir(join(directory, "node_modules/frida"), { recursive: true });
    await mkdir(join(directory, "src/nested"), { recursive: true });
    await Bun.write(join(directory, "node_modules/frida/package.json"), JSON.stringify({ version: "17.23.3" }));
    expect(await client(undefined, { cwd: join(directory, "src/nested") })).toBe("17.23.3");
  });
  test("reads the Frida CLI and reports a missing client explicitly", async () => {
    const directory = await workspace();
    const entry = join(import.meta.dir, "../src/cli.js");
    const detect = () => Bun.spawn([process.execPath, "--eval", `import { client } from ${JSON.stringify(entry)}; try { console.log(await client(undefined, { cwd: ${JSON.stringify(directory)} })); } catch (error) { console.error(error.message); process.exitCode = 1; }`], {
      env: { ...process.env, PATH: directory }, stdout: "pipe", stderr: "pipe",
    });
    const missing = await output(detect());
    expect(missing.code).toBe(1);
    expect(missing.stderr).toContain("No Frida client found");
    await Bun.write(join(directory, "frida"), `#!${process.execPath}\nconsole.log('17.23.3');\n`);
    await Bun.$`chmod +x ${join(directory, "frida")}`.quiet();
    expect(await output(detect())).toEqual({ code: 0, stdout: "17.23.3\n", stderr: "" });
  });
  test("invalid npm client metadata fails loudly", async () => {
    const directory = await workspace();
    await mkdir(join(directory, "node_modules/frida"), { recursive: true });
    await Bun.write(join(directory, "node_modules/frida/package.json"), '{"version":"invalid"}');
    await expect(client(undefined, { cwd: directory })).rejects.toThrow();
  });
});

describe("processes", () => {
  test("drains stdout and stderr concurrently", async () => {
    const result = await execute([process.execPath, "-e", 'console.log("hello"); console.error("diagnostic"); process.exitCode=2']);
    expect(result).toEqual({ code: 2, output: "hello", error: "diagnostic" });
    expect(() => checked(result, "example")).toThrow("diagnostic");
    expect(checked({ code: 0, output: "ok", error: "" }, "example")).toBe("ok");
  });
  test("timeout terminates a stuck command", async () => {
    await expect(execute([process.execPath, "-e", "await Bun.sleep(10000)"], { timeout: 30 })).rejects.toThrow("terminated");
  });
  test("quotes remote shell strings including apostrophes", async () => {
    const text = "a'b; echo injected\n$(id)";
    const result = await execute(["sh", "-c", `printf %s ${quote(text)}`]);
    expect(result.output).toBe(text);
  });
});

describe("CLI", () => {
  test("help and version work without adb", async () => {
    const help = await output(cli(["--help"], { PATH: "" }));
    expect(help.code).toBe(0);
    expect(help.stdout).toContain("--frida-version");
    expect(help.stderr).toBe("");
    const version = await output(cli(["--version"], { PATH: "" }));
    expect(version).toEqual({ code: 0, stdout: "0.1.0\n", stderr: "" });
  });
  test("invalid usage and missing adb return nonzero exit codes", async () => {
    const usage = await output(cli(["--frida-version", "../escape"], { PATH: "" }));
    expect(usage.code).toBe(1);
    expect(usage.stdout).toBe("");
    const missing = await output(cli([], { PATH: "" }));
    expect(missing.code).toBe(1);
    expect(missing.stderr).toContain("adb not found");
  });
  test("run deploys a cached release and reuses the matching service end to end", async () => {
    const directory = await workspace();
    const generation = join(directory, ".cache/frida-run/17.23.3/arm64/.release-12345678-1234-1234-1234-123456789abc");
    await mkdir(generation, { recursive: true });
    const elf = new Uint8Array(64);
    elf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
    const fields = new DataView(elf.buffer);
    fields.setUint16(16, 3, true);
    fields.setUint16(18, 183, true);
    fields.setUint32(20, 1, true);
    fields.setUint16(52, 64, true);
    await Bun.write(join(generation, "frida-server-17.23.3-android-arm64"), elf);
    await Bun.write(join(generation, "metadata.json"), JSON.stringify({
      version: "17.23.3", architecture: "arm64", size: elf.length,
      sha256: new Bun.CryptoHasher("sha256").update(elf).digest("hex"),
      source: { size: 64, digest: null },
    }));
    await Bun.$`ln -s .release-12345678-1234-1234-1234-123456789abc ${join(generation, "../current")}`.quiet();
    const state = join(directory, "running");
    const history = join(directory, "commands");
    await Bun.write(state, "no");
    await Bun.write(history, "[]");
    await Bun.write(join(directory, "adb"), `#!${process.execPath}
const arguments_ = process.argv.slice(2);
const script = arguments_.at(-1);
const history = Bun.file(process.env.FRIDA_TEST_HISTORY);
await Bun.write(history, JSON.stringify([...(await history.json()), arguments_]));
if (arguments_[0] === 'devices') console.log('List of devices attached\\nemulator-5554 device');
else if (script === 'id -u') console.log('0');
else if (script === 'getprop ro.product.cpu.abi') console.log('arm64-v8a');
else if (arguments_[2] === 'push') console.log('1 file pushed');
else if (script.includes('--daemonize')) await Bun.write(process.env.FRIDA_TEST_STATE, 'yes');
else if (script.includes('kill -TERM')) await Bun.write(process.env.FRIDA_TEST_STATE, 'no');
else if (script.includes('for process')) console.log(await Bun.file(process.env.FRIDA_TEST_STATE).text() === 'yes' ? '123' : '');
else if (script.includes('--version')) console.log('17.23.3');
else if (!['mkdir', 'rmdir', 'chmod', 'mv', 'rm'].some(command => script.startsWith(command))) { console.error('Unexpected command: ' + script); process.exitCode = 9; }
`);
    await Bun.$`chmod +x ${join(directory, "adb")}`.quiet();
    const environment = { HOME: directory, PATH: directory, FRIDA_TEST_STATE: state, FRIDA_TEST_HISTORY: history };
    const launched = await output(cli(["--frida-version", "17.23.3"], environment));
    expect(launched.code).toBe(0);
    expect(launched.stderr).toBe("");
    expect(launched.stdout).toContain("17.23.3 is running on emulator-5554 (PID 123)");
    const initial = await Bun.file(history).json();
    expect(initial.some((arguments_) => arguments_[2] === "push")).toBe(true);
    await Bun.write(history, "[]");
    const reused = await output(cli(["--frida-version", "17.23.3"], environment));
    expect(reused.code).toBe(0);
    expect(reused.stdout).toContain("already running");
    const subsequent = await Bun.file(history).json();
    expect(subsequent.some((arguments_) => arguments_[2] === "push" || arguments_.at(-1).includes("kill -TERM"))).toBe(false);
  });
  test("status and stop operate through an actual fake adb executable without touching devices", async () => {
    const directory = await workspace();
    const state = join(directory, "running");
    await Bun.write(state, "yes");
    await Bun.write(join(directory, "adb"), `#!${process.execPath}
const arguments_ = process.argv.slice(2);
const script = arguments_.at(-1);
if (arguments_[0] === 'devices') console.log('List of devices attached\\nemulator-5554 device product:test');
else if (script === 'id -u') console.log('0');
else if (script.includes('kill -TERM')) await Bun.write(process.env.FRIDA_TEST_STATE, 'no');
else if (script.includes('for process')) console.log(await Bun.file(process.env.FRIDA_TEST_STATE).text() === 'yes' ? '123' : '');
else if (script.includes('--version')) console.log('17.23.3');
else if (!['mkdir', 'rmdir'].some(command => script.startsWith(command))) { console.error('Unexpected command: ' + script); process.exitCode = 9; }
`);
    await Bun.$`chmod +x ${join(directory, "adb")}`.quiet();
    const environment = { PATH: directory, FRIDA_TEST_STATE: state };
    const running = await output(cli(["status"], environment));
    expect(running.code).toBe(0);
    expect(running.stdout).toContain("17.23.3 is running (PID 123)");
    const stopped = await output(cli(["stop"], environment));
    expect(stopped.code).toBe(0);
    expect(stopped.stdout).toContain("frida-server stopped.");
    const absent = await output(cli(["status"], environment));
    expect(absent.code).toBe(0);
    expect(absent.stdout).toContain("not running");
  });
});
