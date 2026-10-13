// SPDX-License-Identifier: GPL-3.0-only
import { checked, execute, quote } from "./process.js";

export function devices(output) {
  return output.split(/\r?\n/).flatMap((line) => {
    const match = line.match(/^(\S+)\s+(device|offline|unauthorized|recovery|sideload|bootloader|no permissions)(?:\s|$)/);
    return match ? [{ serial: match[1], state: match[2] }] : [];
  });
}

export function select(connected, serial) {
  if (serial) {
    const device = connected.find((device) => device.serial === serial);
    if (!device) throw new Error(`Device ${serial} not found.`);
    if (device.state !== "device") throw new Error(`Device ${serial} is ${device.state}; check the connection and authorize USB debugging.`);
    return device.serial;
  }
  const available = connected.filter(({ state }) => state === "device");
  if (!available.length) throw new Error(`No ready Android device found.${connected.length ? ` Connected: ${connected.map(({ serial, state }) => `${serial} (${state})`).join(", ")}.` : ""}`);
  if (available.length > 1) throw new Error(`Multiple devices available; select one with --device: ${available.map(({ serial }) => serial).join(", ")}.`);
  return available[0].serial;
}

export function architecture(abi) {
  const architectures = { armeabi: "arm", "armeabi-v7a": "arm", "arm64-v8a": "arm64", x86: "x86", x86_64: "x86_64" };
  if (!Object.hasOwn(architectures, abi)) throw new Error(`Unsupported Android ABI: ${abi || "empty"}.`);
  return architectures[abi];
}

export class Device {
  constructor(serial, { adb = "adb", execute: command = execute } = {}) {
    this.serial = serial;
    this.adb = adb;
    this.execute = command;
  }

  async command(...arguments_) {
    return checked(await this.execute([this.adb, "-s", this.serial, ...arguments_]), `ADB on ${this.serial}`);
  }

  async shell(script) {
    return this.command("shell", script);
  }

  async architecture() {
    return architecture(await this.shell("getprop ro.product.cpu.abi"));
  }

  async authorize() {
    const identity = await this.execute([this.adb, "-s", this.serial, "shell", "id -u"]);
    if (checked(identity, "Reading device identity") === "0") {
      this.privilege = (script) => script;
      return;
    }
    const failures = [];
    for (const privilege of [(script) => `su -c ${quote(script)}`, (script) => `su 0 sh -c ${quote(script)}`]) {
      const { code, output, error } = await this.execute([this.adb, "-s", this.serial, "shell", privilege("id -u")]);
      if (code === 0 && output === "0") {
        this.privilege = privilege;
        return;
      }
      failures.push(error || output || `exit ${code}`);
    }
    throw new Error(`Root access required on ${this.serial}. Authorize ADB shell in your root app. ${failures.join("; ")}`);
  }

  async root(script) {
    return this.shell(this.privilege(script));
  }
}
