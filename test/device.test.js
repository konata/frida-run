// SPDX-License-Identifier: GPL-3.0-only
import { describe, expect, mock, test } from "bun:test";
import { architecture, Device, devices, select } from "../src/device.js";

const result = (output = "", code = 0, error = "") => ({ code, output, error });

function connection(replies, { serial = "phone", adb = "adb" } = {}) {
  const pending = [...replies];
  const execute = mock(async () => {
    if (!pending.length) throw new Error("Unexpected ADB invocation in test");
    const reply = pending.shift();
    if (reply instanceof Error) throw reply;
    return reply;
  });
  return { device: new Device(serial, { adb, execute }), execute };
}

const connected = [
  { serial: "phone", state: "device" },
  { serial: "disconnected", state: "offline" },
  { serial: "untrusted", state: "unauthorized" },
  { serial: "restricted", state: "no permissions" },
];

describe("ADB device list", () => {
  test.each(["\n", "\r\n"])("parses ready and non-ready devices with %j separators", (newline) => {
    const listing = [
      "* daemon not running; starting now at tcp:5037",
      "* daemon started successfully",
      "List of devices attached",
      "phone\tdevice product:pixel model:Pixel device:pixel transport_id:1",
      "disconnected\toffline transport_id:2",
      "untrusted\tunauthorized transport_id:3",
      "restricted\tno permissions (user in plugdev group; are your udev rules wrong?)",
      "",
    ].join(newline);
    expect(devices(listing)).toEqual(connected);
  });

  test("retains other recognized Android states without treating noise as a device", () => {
    expect(devices("rescue recovery\nupdate sideload\nloader bootloader\ninvalid devices\ninvalid unknown\n"))
      .toEqual([
        { serial: "rescue", state: "recovery" },
        { serial: "update", state: "sideload" },
        { serial: "loader", state: "bootloader" },
      ]);
    expect(devices("List of devices attached\r\n\r\n")).toEqual([]);
    expect(devices("")).toEqual([]);
  });
});

describe("device selection", () => {
  test("selects the only ready device among offline and unauthorized connections", () => {
    expect(select(connected)).toBe("phone");
  });

  test("requires an explicit serial for multiple ready devices", () => {
    const multiple = [...connected, { serial: "tablet", state: "device" }];
    expect(() => select(multiple)).toThrow("Multiple devices available; select one with --device: phone, tablet.");
    expect(select(multiple, "tablet")).toBe("tablet");
  });

  test("rejects an unknown explicit serial rather than selecting another device", () => {
    expect(() => select(connected, "missing")).toThrow("Device missing not found.");
  });

  test.each(["offline", "unauthorized", "no permissions", "recovery", "sideload", "bootloader"])(
    "rejects an explicitly selected %s device", (state) => {
      expect(() => select([...connected, { serial: "target", state }], "target"))
        .toThrow(`Device target is ${state}; check the connection and authorize USB debugging.`);
    },
  );

  test("reports no ready devices and includes connected states", () => {
    expect(() => select([])).toThrow("No ready Android device found.");
    expect(() => select(connected.slice(1))).toThrow(
      "No ready Android device found. Connected: disconnected (offline), untrusted (unauthorized), restricted (no permissions).",
    );
  });
});

describe("Android ABI", () => {
  test.each([
    ["armeabi", "arm"],
    ["armeabi-v7a", "arm"],
    ["arm64-v8a", "arm64"],
    ["x86", "x86"],
    ["x86_64", "x86_64"],
  ])("maps %s to %s", (abi, expected) => {
    expect(architecture(abi)).toBe(expected);
  });

  test.each(["", "riscv64", "arm64", "toString", "__proto__"])("rejects unsupported ABI %j", (abi) => {
    expect(() => architecture(abi)).toThrow(`Unsupported Android ABI: ${abi || "empty"}.`);
  });

  test("reads the selected device ABI through getprop", async () => {
    const { device, execute } = connection([result("arm64-v8a")]);
    expect(await device.architecture()).toBe("arm64");
    expect(execute).toHaveBeenCalledWith(["adb", "-s", "phone", "shell", "getprop ro.product.cpu.abi"]);
  });

  test("rejects an unsupported ABI returned by getprop", async () => {
    const { device } = connection([result("riscv64")]);
    await expect(device.architecture()).rejects.toThrow("Unsupported Android ABI: riscv64.");
  });
});

describe("Device commands", () => {
  test("passes executable, serial, paths and shell scripts as argv, never through a host shell", async () => {
    const adb = "/tools/adb with spaces; touch /host-owned";
    const serial = "phone; $(touch /host-owned)";
    const script = "printf '%s' '$HOME'; echo \"$(id)\"";
    const { device, execute } = connection([result("uploaded"), result("printed")], { adb, serial });
    expect(await device.command("push", "/local/server with spaces;$(id)", "/remote/server")).toBe("uploaded");
    expect(await device.shell(script)).toBe("printed");
    expect(execute.mock.calls).toEqual([
      [[adb, "-s", serial, "push", "/local/server with spaces;$(id)", "/remote/server"]],
      [[adb, "-s", serial, "shell", script]],
    ]);
  });

  test.each([
    [result("fallback output", 7, "device offline"), "device offline"],
    [result("permission denied", 9), "permission denied"],
    [result("", 1), "no diagnostic output"],
  ])("rejects nonzero ADB results with useful diagnostics", async (reply, diagnostic) => {
    const { device } = connection([reply]);
    await expect(device.shell("id -u")).rejects.toThrow(`ADB on phone failed (${reply.code}): ${diagnostic}`);
  });

  test("propagates command execution errors", async () => {
    const failure = new Error("ADB executable not found");
    const { device } = connection([failure]);
    await expect(device.command("get-state")).rejects.toBe(failure);
  });
});

describe("root authorization", () => {
  test("uses root adbd directly without invoking su", async () => {
    const { device, execute } = connection([result("0"), result("root output")]);
    await device.authorize();
    expect(await device.root("printf 'root output'")).toBe("root output");
    expect(execute.mock.calls).toEqual([
      [["adb", "-s", "phone", "shell", "id -u"]],
      [["adb", "-s", "phone", "shell", "printf 'root output'"]],
    ]);
  });

  test("uses su -c and escapes embedded single quotes as one remote script", async () => {
    const { device, execute } = connection([result("2000"), result("0"), result("ready")]);
    await device.authorize();
    expect(await device.root("printf '%s' \"$HOME\"; id -u")).toBe("ready");
    expect(execute.mock.calls).toEqual([
      [["adb", "-s", "phone", "shell", "id -u"]],
      [["adb", "-s", "phone", "shell", "su -c 'id -u'"]],
      [["adb", "-s", "phone", "shell", "su -c 'printf '\\''%s'\\'' \"$HOME\"; id -u'"]],
    ]);
  });

  test("falls back to su 0 sh -c when su -c fails", async () => {
    const { device, execute } = connection([
      result("2000"), result("", 1, "unsupported -c"), result("0"), result("root output"),
    ]);
    await device.authorize();
    expect(await device.root("id -u")).toBe("root output");
    expect(execute.mock.calls).toEqual([
      [["adb", "-s", "phone", "shell", "id -u"]],
      [["adb", "-s", "phone", "shell", "su -c 'id -u'"]],
      [["adb", "-s", "phone", "shell", "su 0 sh -c 'id -u'"]],
      [["adb", "-s", "phone", "shell", "su 0 sh -c 'id -u'"]],
    ]);
  });

  test("rejects nonzero su exits even when they print zero", async () => {
    const { device, execute } = connection([result("2000"), result("0", 1), result("0", 2)]);
    await expect(device.authorize()).rejects.toThrow("Root access required on phone.");
    expect(execute).toHaveBeenCalledTimes(3);
    expect(device.privilege).toBeUndefined();
  });

  test.each(["uid=0(root) gid=0(root)", "0\npermission denied", "000", "2000"])(
    "does not accept misleading identity output %j", async (identity) => {
      const { device, execute } = connection([result(identity), result(identity), result(identity)]);
      await expect(device.authorize()).rejects.toThrow("Root access required on phone.");
      expect(execute).toHaveBeenCalledTimes(3);
      expect(device.privilege).toBeUndefined();
    },
  );

  test("reports both su failure diagnostics", async () => {
    const { device } = connection([result("2000"), result("", 1, "denied by root app"), result("", 127)]);
    await expect(device.authorize()).rejects.toThrow("denied by root app; exit 127");
  });

  test("does not try su when the initial ADB identity command fails", async () => {
    const { device, execute } = connection([result("0", 1, "device unauthorized")]);
    await expect(device.authorize()).rejects.toThrow("Reading device identity failed (1): device unauthorized");
    expect(execute).toHaveBeenCalledTimes(1);
  });

  test("propagates ADB execution failures during su authorization", async () => {
    const failure = new Error("ADB connection lost");
    const { device, execute } = connection([result("2000"), failure]);
    await expect(device.authorize()).rejects.toBe(failure);
    expect(execute).toHaveBeenCalledTimes(2);
  });

  test("rejects nonzero commands after successful root authorization", async () => {
    const { device } = connection([result("0"), result("", 13, "root command denied")]);
    await device.authorize();
    await expect(device.root("chmod 0755 /server")).rejects.toThrow("ADB on phone failed (13): root command denied");
  });
});
