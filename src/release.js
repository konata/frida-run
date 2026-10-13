// SPDX-License-Identifier: GPL-3.0-only
import { chmod, mkdir, mkdtemp, readlink, rename, rm, symlink } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, join, resolve } from "node:path";

const architectures = { arm: [1, 40], arm64: [2, 183], x86: [1, 3], x86_64: [2, 62] };
const hexadecimal = /^[a-f0-9]{64}$/i;

export function version(input) {
  if (typeof input !== "string" || input.match(/^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$/)?.[0] !== input)
    throw new Error(`Invalid Frida version: ${String(input)}; expected three numeric components, e.g. 17.23.3`);
  return input;
}

class InvalidServer extends Error {}

async function stream(filename, content) {
  const writer = Bun.file(filename).writer();
  try {
    for await (const chunk of content) {
      writer.write(chunk);
      await writer.flush();
    }
  } finally {
    await writer.end();
  }
}

async function checksum(filename) {
  const digest = new Bun.CryptoHasher("sha256");
  for await (const chunk of Bun.file(filename).stream()) digest.update(chunk);
  return digest.digest("hex");
}

async function server(filename, architecture) {
  const binary = Bun.file(filename);
  if (!binary.size) throw new InvalidServer("Invalid Frida server: empty binary");
  const header = new Uint8Array(await binary.slice(0, 64).arrayBuffer());
  const [format, machine] = architectures[architecture];
  const length = format === 1 ? 52 : 64;
  const fields = new DataView(header.buffer, header.byteOffset, header.byteLength);
  if (header.length < length || header[0] !== 0x7f || header[1] !== 0x45 || header[2] !== 0x4c || header[3] !== 0x46 ||
      header[4] !== format || header[5] !== 1 || header[6] !== 1 || ![2, 3].includes(fields.getUint16(16, true)) ||
      fields.getUint16(18, true) !== machine || fields.getUint32(20, true) !== 1 ||
      fields.getUint16(format === 1 ? 40 : 52, true) !== length)
    throw new InvalidServer(`Invalid Frida server: ELF header does not match Android ${architecture}`);
  return { size: binary.size, sha256: await checksum(filename) };
}

async function cached(directory, number, architecture) {
  try {
    const pointer = await readlink(join(directory, "current"));
    if (!/^\.release-[0-9a-f-]{36}$/.test(pointer)) return;
    const generation = join(directory, pointer);
    const metadata = await Bun.file(join(generation, "metadata.json")).json();
    if (metadata?.version !== number || metadata.architecture !== architecture || !hexadecimal.test(metadata.sha256) ||
        !Number.isSafeInteger(metadata.size) || metadata.size <= 0 || !Number.isSafeInteger(metadata.source?.size) ||
        metadata.source.size <= 0 || !(metadata.source.digest === null || typeof metadata.source.digest === "string")) return;
    const filename = join(generation, `frida-server-${number}-android-${architecture}`);
    const binary = await server(filename, architecture);
    if (binary.size === metadata.size && binary.sha256 === metadata.sha256) return { version: number, filename };
  } catch (error) {
    if (!["ENOENT", "ENOTDIR", "EINVAL", "ELOOP"].includes(error.code) && !(error instanceof SyntaxError) && !(error instanceof InvalidServer)) throw error;
  }
}

export async function release(requested, architecture, {
  directory = join(homedir(), ".cache/frida-run"), force = false, fetch: request = globalThis.fetch,
  api = "https://api.github.com/repos/frida/frida", echo = console.log,
} = {}) {
  if (!Object.hasOwn(architectures, architecture)) throw new Error(`Unsupported Android architecture: ${architecture}`);
  let number = requested === "latest" ? undefined : version(requested);
  const root = resolve(directory);
  if (number && !force) {
    const hit = await cached(join(root, number, architecture), number, architecture);
    if (hit) return hit;
  }

  async function response(url) {
    try {
      const reply = await request(url, { signal: AbortSignal.timeout(60_000) });
      if (!reply.ok) {
        await reply.body?.cancel();
        const hint = [403, 429].includes(reply.status) ? "; rate limit or access denied: retry later and check GitHub access" : "";
        throw new Error(`Frida request failed: HTTP ${reply.status} ${reply.statusText} at ${url}${hint}`);
      }
      return reply;
    } catch (error) {
      if (["AbortError", "TimeoutError"].includes(error.name)) throw new Error(`Frida download timed out after 60 seconds at ${url}`, { cause: error });
      throw error;
    }
  }

  const publication = await (await response(`${api.replace(/\/+$/, "")}/releases/${number ? `tags/${number}` : "latest"}`)).json();
  const tag = version(publication.tag_name);
  if (number && tag !== number) throw new Error(`Frida release tag mismatch: expected ${number}, received ${tag}`);
  number = tag;
  const cache = join(root, number, architecture);
  if (requested === "latest" && !force) {
    const hit = await cached(cache, number, architecture);
    if (hit) return hit;
  }
  const name = `frida-server-${number}-android-${architecture}`;
  const asset = publication.assets?.find(({ name: filename }) => filename === `${name}.xz`);
  if (!asset) throw new Error(`Frida ${number} has no Android ${architecture} server asset (${name}.xz)`);
  if (!Number.isSafeInteger(asset.size) || asset.size <= 0) throw new Error(`Invalid Frida asset size: ${asset.size}`);
  const digest = /^sha256:/i.test(asset.digest ?? "") ? asset.digest.slice(7) : undefined;
  if (digest !== undefined && !hexadecimal.test(digest)) throw new Error(`Invalid Frida asset SHA-256 digest: ${asset.digest}`);

  await mkdir(cache, { recursive: true });
  let staging = await mkdtemp(join(cache, ".download-"));
  const generation = join(cache, `.release-${crypto.randomUUID()}`);
  const pointer = `${generation}.link`;
  let complete = false;
  try {
    echo(`Downloading Frida ${number} for Android ${architecture}`);
    const archive = join(staging, `${name}.xz`);
    const downloaded = await response(asset.browser_download_url);
    if (!downloaded.body) throw new Error("Frida asset response has no body");
    await stream(archive, downloaded.body);
    if (Bun.file(archive).size !== asset.size) throw new Error(`Frida asset size mismatch: expected ${asset.size}, received ${Bun.file(archive).size}`);
    if (digest !== undefined && await checksum(archive) !== digest.toLowerCase()) throw new Error("Frida asset SHA-256 digest mismatch");

    const filename = join(staging, name);
    const decompression = Bun.spawn(["xz", "--decompress", "--stdout", archive], {
      stdin: "ignore", stdout: "pipe", stderr: "pipe", timeout: 60_000,
    });
    const diagnostic = new Response(decompression.stderr).text();
    try {
      await stream(filename, decompression.stdout);
    } catch (error) {
      decompression.kill();
      await decompression.exited;
      await diagnostic;
      throw error;
    }
    const status = await decompression.exited;
    const failure = await diagnostic;
    if (status !== 0) throw new Error(`Frida xz decompression failed (exit ${status}): ${failure.trim()}`);
    const binary = await server(filename, architecture);
    await chmod(filename, 0o755);
    await Bun.write(join(staging, "metadata.json"), JSON.stringify({
      version: number, architecture, ...binary, source: { size: asset.size, digest: asset.digest ?? null },
    }));
    await rm(archive);
    await rename(staging, generation);
    staging = generation;
    // One atomic pointer publishes an immutable binary/metadata pair; old paths stay usable.
    await symlink(basename(generation), pointer);
    await rename(pointer, join(cache, "current"));
    complete = true;
    return { version: number, filename: join(generation, name) };
  } catch (error) {
    if (["AbortError", "TimeoutError"].includes(error.name)) throw new Error("Frida download timed out after 60 seconds", { cause: error });
    throw error;
  } finally {
    if (!complete) await rm(staging, { recursive: true, force: true });
    await rm(pointer, { force: true });
  }
}
