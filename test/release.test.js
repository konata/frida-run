import { afterEach, expect, test } from "bun:test";
import { mkdtemp, readdir, rm, stat, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import { release, version } from "../src/release.js";

const number = "17.23.3";
const architectures = { arm: [1, 40], arm64: [2, 183], x86: [1, 3], x86_64: [2, 62] };
const cleanup = [];

afterEach(async () => {
  for (const dispose of cleanup.splice(0).reverse()) await dispose();
});

function elf(architecture = "arm64", revision = 0) {
  const [format, machine] = architectures[architecture];
  const binary = Buffer.alloc(512, revision);
  binary.set([0x7f, 0x45, 0x4c, 0x46, format, 1, 1]);
  binary.writeUInt16LE(3, 16);
  binary.writeUInt16LE(machine, 18);
  binary.writeUInt32LE(1, 20);
  binary.writeUInt16LE(format === 1 ? 52 : 64, format === 1 ? 40 : 52);
  return binary;
}

async function archive(binary) {
  const compression = Bun.spawn(["xz", "--compress", "--stdout"], { stdin: binary, stdout: "pipe", stderr: "pipe" });
  const [compressed, diagnostic, status] = await Promise.all([
    new Response(compression.stdout).bytes(), new Response(compression.stderr).text(), compression.exited,
  ]);
  if (status) throw new Error(`xz fixture failed: ${diagnostic}`);
  return new Uint8Array(compressed);
}

async function fixture(architecture = "arm64", binary = elf(architecture)) {
  const directory = await mkdtemp(join(tmpdir(), "frida-release-"));
  cleanup.push(() => rm(directory, { recursive: true, force: true }));
  const publication = {
    binary, compressed: await archive(binary), tag: number, architecture, size: undefined, digest: undefined,
    publicationStatus: 200, downloadStatus: 200, delay: 0, redirect: false,
  };
  const requests = [];
  const redirects = [];
  const destination = Bun.serve({
    hostname: "127.0.0.1", port: 0,
    fetch(request) {
      redirects.push(request);
      return new Response(publication.compressed);
    },
  });
  cleanup.push(() => destination.stop(true));
  const http = Bun.serve({
    hostname: "127.0.0.1", port: 0,
    async fetch(request) {
      const path = new URL(request.url).pathname;
      requests.push({ path, authorization: request.headers.get("authorization") });
      if (path.startsWith("/releases/")) {
        if (publication.publicationStatus !== 200) return new Response("failure", { status: publication.publicationStatus });
        return Response.json({
          tag_name: publication.tag,
          assets: [{
            name: `frida-server-${publication.tag}-android-${publication.architecture}.xz`,
            size: publication.size ?? publication.compressed.length,
            digest: publication.digest === undefined ? `sha256:${Bun.SHA256.hash(publication.compressed, "hex")}` : publication.digest,
            browser_download_url: `${http.url}archive`,
          }],
        });
      }
      if (path === "/archive") {
        if (publication.downloadStatus !== 200) return new Response("failure", { status: publication.downloadStatus });
        if (publication.redirect) return Response.redirect(`${destination.url}binary`);
        const compressed = publication.compressed;
        return new Response(new ReadableStream({
          async start(controller) {
            try {
              if (publication.delay) await Bun.sleep(publication.delay);
              for (let offset = 0; offset < compressed.length; offset += 65536) controller.enqueue(compressed.slice(offset, offset + 65536));
              controller.close();
            } catch (error) {
              controller.error(error);
            }
          },
        }));
      }
      return new Response("not found", { status: 404 });
    },
  });
  cleanup.push(() => http.stop(true));
  const options = { directory, api: http.url.href.replace(/\/$/, ""), echo() {} };
  return { directory, publication, requests, redirects, options };
}

test("version", () => {
  for (const input of [number, "0.0.0", "1.20.300"]) expect(version(input)).toBe(input);
  for (const input of ["latest", "v17.23.3", "17.23", "17.23.3.0", "01.2.3", "1.02.3", "1.2.03", "-1.2.3",
    "1.2.3-beta", "1.2.3\n", " 1.2.3", "", 123, null, undefined]) expect(() => version(input)).toThrow("Invalid Frida version");
});

test.each(Object.keys(architectures))("download %s", async architecture => {
  const { publication, requests, options } = await fixture(architecture);
  const result = await release(number, architecture, options);
  expect(result.version).toBe(number);
  expect(isAbsolute(result.filename)).toBe(true);
  expect(result.filename.startsWith(join(options.directory, number, architecture))).toBe(true);
  expect(await Bun.file(result.filename).bytes()).toEqual(publication.binary);
  expect((await stat(result.filename)).mode & 0o777).toBe(0o755);
  expect(await Bun.file(join(dirname(result.filename), "metadata.json")).json()).toEqual({
    version: number, architecture, size: publication.binary.length, sha256: Bun.SHA256.hash(publication.binary, "hex"),
    source: { size: publication.compressed.length, digest: `sha256:${Bun.SHA256.hash(publication.compressed, "hex")}` },
  });
  expect(requests.map(({ path }) => path)).toEqual([`/releases/tags/${number}`, "/archive"]);
  expect((await readdir(dirname(result.filename))).sort()).toEqual([`frida-server-${number}-android-${architecture}`, "metadata.json"]);
});

test("cache offline", async () => {
  const { options, requests } = await fixture();
  const first = await release(number, "arm64", options);
  const second = await release(number, "arm64", { ...options, fetch() { throw new Error("must stay offline"); } });
  expect(second).toEqual(first);
  expect(requests).toHaveLength(2);
});

test("force", async () => {
  const { publication, options, requests } = await fixture();
  const first = await release(number, "arm64", options);
  publication.binary = elf("arm64", 1);
  publication.compressed = await archive(publication.binary);
  const second = await release(number, "arm64", { ...options, force: true });
  expect(second.filename).not.toBe(first.filename);
  expect(await Bun.file(second.filename).bytes()).toEqual(publication.binary);
  expect(await Bun.file(first.filename).bytes()).toEqual(elf());
  expect(await release(number, "arm64", options)).toEqual(second);
  expect(requests).toHaveLength(4);
});

test.each(["binary", "metadata", "checksum", "missing", "header"])("corrupt %s", async corruption => {
  const { options, requests } = await fixture();
  const first = await release(number, "arm64", options);
  const filename = join(dirname(first.filename), "metadata.json");
  if (corruption === "binary") await Bun.write(first.filename, elf("arm64", 2));
  if (corruption === "metadata") await Bun.write(filename, "{");
  if (corruption === "checksum") {
    const metadata = await Bun.file(filename).json();
    await Bun.write(filename, JSON.stringify({ ...metadata, sha256: "0".repeat(64) }));
  }
  if (corruption === "missing") await rm(first.filename);
  if (corruption === "header") {
    const binary = elf("x86_64");
    await Bun.write(first.filename, binary);
    const metadata = await Bun.file(filename).json();
    await Bun.write(filename, JSON.stringify({ ...metadata, sha256: Bun.SHA256.hash(binary, "hex") }));
  }
  const replacement = await release(number, "arm64", options);
  expect(replacement.filename).not.toBe(first.filename);
  expect(await Bun.file(replacement.filename).bytes()).toEqual(elf());
  expect(requests).toHaveLength(4);
});

test.each(["http", "digest", "xz", "elf"])("force preserves %s", async failure => {
  const { publication, options } = await fixture();
  const first = await release(number, "arm64", options);
  const before = await Bun.file(join(dirname(first.filename), "metadata.json")).text();
  if (failure === "http") publication.downloadStatus = 500;
  if (failure === "digest") publication.digest = `sha256:${"0".repeat(64)}`;
  if (failure === "xz") publication.compressed = new TextEncoder().encode("broken xz");
  if (failure === "elf") publication.compressed = await archive(Buffer.from("not ELF"));
  await expect(release(number, "arm64", { ...options, force: true })).rejects.toThrow();
  expect(await release(number, "arm64", { ...options, fetch() { throw new Error("offline"); } })).toEqual(first);
  expect(await Bun.file(first.filename).bytes()).toEqual(elf());
  expect(await Bun.file(join(dirname(first.filename), "metadata.json")).text()).toBe(before);
  expect((await readdir(join(options.directory, number, "arm64"))).sort()).toEqual([dirname(first.filename).split("/").at(-1), "current"].sort());
});

test("latest", async () => {
  const { publication, options, requests } = await fixture();
  expect((await release("latest", "arm64", options)).version).toBe(number);
  requests.length = 0;
  const hit = await release("latest", "arm64", options);
  expect(requests.map(({ path }) => path)).toEqual(["/releases/latest"]);
  publication.tag = "17.24.0";
  const newer = await release("latest", "arm64", options);
  expect(newer.version).toBe("17.24.0");
  expect(newer.filename).not.toBe(hit.filename);
});

test("missing architecture", async () => {
  const { options, requests } = await fixture("arm");
  await expect(release(number, "arm64", options)).rejects.toThrow("has no Android arm64 server asset");
  expect(requests).toHaveLength(1);
});

test("invalid request", async () => {
  const { options, requests } = await fixture();
  await expect(release("v17.23.3", "arm64", options)).rejects.toThrow("Invalid Frida version");
  await expect(release(number, "mips", options)).rejects.toThrow("Unsupported Android architecture");
  await expect(release(number, "toString", options)).rejects.toThrow("Unsupported Android architecture");
  expect(requests).toHaveLength(0);
});

test.each([403, 429, 404, 500])("metadata HTTP %s", async status => {
  const { publication, options } = await fixture();
  publication.publicationStatus = status;
  await expect(release(number, "arm64", options)).rejects.toThrow(`HTTP ${status}`);
  if ([403, 429].includes(status)) await expect(release(number, "arm64", options)).rejects.toThrow("retry later");
});

test.each([403, 429, 404, 500])("asset HTTP %s", async status => {
  const { publication, options, directory } = await fixture();
  publication.downloadStatus = status;
  await expect(release(number, "arm64", options)).rejects.toThrow(`HTTP ${status}`);
  expect(await readdir(join(directory, number, "arm64"))).toEqual([]);
});

test("size", async () => {
  const { publication, options } = await fixture();
  publication.size = publication.compressed.length + 1;
  await expect(release(number, "arm64", options)).rejects.toThrow("asset size mismatch");
  publication.size = 0;
  await expect(release(number, "arm64", options)).rejects.toThrow("Invalid Frida asset size");
});

test("digest", async () => {
  const { publication, options } = await fixture();
  publication.digest = `sha256:${"0".repeat(64)}`;
  await expect(release(number, "arm64", options)).rejects.toThrow("SHA-256 digest mismatch");
  publication.digest = "sha256:invalid";
  await expect(release(number, "arm64", options)).rejects.toThrow("Invalid Frida asset SHA-256 digest");
});

test("no digest", async () => {
  const { publication, options } = await fixture();
  publication.digest = null;
  const result = await release(number, "arm64", options);
  const metadata = await Bun.file(join(dirname(result.filename), "metadata.json")).json();
  expect(metadata.source.digest).toBeNull();
  expect(metadata.sha256).toBe(Bun.SHA256.hash(publication.binary, "hex"));
  expect(await release(number, "arm64", options)).toEqual(result);
});

test.each(["broken", "truncated"])("xz %s", async corruption => {
  const { publication, options, directory } = await fixture();
  publication.compressed = corruption === "broken" ? Buffer.from("not xz") : publication.compressed.slice(0, -10);
  await expect(release(number, "arm64", options)).rejects.toThrow("xz decompression failed");
  expect(await readdir(join(directory, number, "arm64"))).toEqual([]);
});

test.each(["empty", "text", "short", "machine", "class", "endian", "type", "length"])("ELF %s", async corruption => {
  let binary = elf();
  if (corruption === "empty") binary = Buffer.alloc(0);
  if (corruption === "text") binary = Buffer.from("not an ELF server");
  if (corruption === "short") binary = binary.slice(0, 20);
  if (corruption === "machine") binary = elf("x86_64");
  if (corruption === "class") binary[4] = 1;
  if (corruption === "endian") binary[5] = 2;
  if (corruption === "type") binary.writeUInt16LE(1, 16);
  if (corruption === "length") binary.writeUInt16LE(0, 52);
  const { options, directory } = await fixture("arm64", binary);
  await expect(release(number, "arm64", options)).rejects.toThrow("Invalid Frida server");
  expect(await readdir(join(directory, number, "arm64"))).toEqual([]);
});

test("tag mismatch", async () => {
  const { publication, options } = await fixture();
  publication.tag = "17.23.4";
  await expect(release(number, "arm64", options)).rejects.toThrow("release tag mismatch");
  publication.tag = "v17.23.3";
  await expect(release("latest", "arm64", options)).rejects.toThrow("Invalid Frida version");
});

test("timeout", async () => {
  const { publication, options, directory } = await fixture();
  publication.delay = 200;
  await expect(release(number, "arm64", {
    ...options,
    fetch(url, { signal }) {
      expect(signal).toBeInstanceOf(AbortSignal);
      return fetch(url, { signal: url.endsWith("/archive") ? AbortSignal.timeout(25) : signal });
    },
  })).rejects.toThrow("timed out");
  expect(await readdir(join(directory, number, "arm64"))).toEqual([]);
});

test("concurrent", async () => {
  const { options, publication } = await fixture();
  const results = await Promise.all(Array.from({ length: 6 }, () => release(number, "arm64", options)));
  expect(new Set(results.map(({ filename }) => filename)).size).toBe(6);
  for (const { filename } of results) {
    const metadata = await Bun.file(join(dirname(filename), "metadata.json")).json();
    expect(await Bun.file(filename).bytes()).toEqual(publication.binary);
    expect(metadata.sha256).toBe(await Bun.file(filename).bytes().then(binary => Bun.SHA256.hash(binary, "hex")));
  }
  const hit = await release(number, "arm64", { ...options, fetch() { throw new Error("offline"); } });
  expect(results).toContainEqual(hit);
  expect((await readdir(join(options.directory, number, "arm64"))).filter(name => name.startsWith(".download-") || name.endsWith(".link"))).toEqual([]);
});

test("read during force", async () => {
  const { publication, options } = await fixture();
  const first = await release(number, "arm64", options);
  publication.compressed = await archive(elf("arm64", 1));
  publication.delay = 100;
  const replacement = release(number, "arm64", { ...options, force: true });
  const current = await release(number, "arm64", { ...options, fetch() { throw new Error("offline"); } });
  expect(current).toEqual(first);
  const second = await replacement;
  expect(await release(number, "arm64", options)).toEqual(second);
  expect(await Bun.file(first.filename).bytes()).toEqual(elf());
});

test.each(["regular", "outside", "partial"])("pointer %s", async corruption => {
  const { options } = await fixture();
  const first = await release(number, "arm64", options);
  const pointer = join(options.directory, number, "arm64", "current");
  await rm(pointer);
  if (corruption === "regular") await Bun.write(pointer, "broken pointer");
  if (corruption === "outside") await symlink(dirname(first.filename), pointer);
  if (corruption === "partial") await symlink(".download-incomplete", pointer);
  const second = await release(number, "arm64", options);
  expect(second.filename).not.toBe(first.filename);
  expect(await release(number, "arm64", options)).toEqual(second);
});

test("stream", async () => {
  const binary = Buffer.alloc(2 * 1024 * 1024);
  for (let offset = 0; offset < binary.length; offset += 65536) crypto.getRandomValues(binary.subarray(offset, offset + 65536));
  binary.set(elf());
  const { options } = await fixture("arm64", binary);
  const result = await release(number, "arm64", {
    ...options,
    async fetch(url, options) {
      const response = await fetch(url, options);
      if (!url.endsWith("/archive")) return response;
      for (const method of ["arrayBuffer", "bytes", "text", "blob"]) response[method] = () => { throw new Error("must stream asset"); };
      return response;
    },
  });
  expect(await Bun.file(result.filename).bytes()).toEqual(binary);
});

test("redirect without token", async () => {
  const { publication, options, requests, redirects } = await fixture();
  const token = process.env.GITHUB_TOKEN;
  process.env.GITHUB_TOKEN = "never-send-this";
  cleanup.push(() => { if (token === undefined) delete process.env.GITHUB_TOKEN; else process.env.GITHUB_TOKEN = token; });
  publication.redirect = true;
  const result = await release(number, "arm64", options);
  expect(await Bun.file(result.filename).bytes()).toEqual(publication.binary);
  expect(requests.every(({ authorization }) => authorization === null)).toBe(true);
  expect(redirects).toHaveLength(1);
  expect(redirects[0].headers.get("authorization")).toBeNull();
});
