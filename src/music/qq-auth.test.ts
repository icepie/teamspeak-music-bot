import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { QqPollCredentials } from "./qq-auth.js";

interface TestSocket {
  url: string;
  sent: Buffer[];
  terminated: boolean;
  emit(event: string, ...args: unknown[]): boolean;
  terminate(): void;
}
const { sockets, get, post } = vi.hoisted(() => ({
  sockets: [] as TestSocket[], get: vi.fn(), post: vi.fn(),
}));
vi.mock("axios", () => ({ default: { create: () => ({ get, post }) } }));
vi.mock("ws", async () => {
  // Vitest hoists this factory before static imports are initialized.
  const { EventEmitter } = await import("node:events");
  class Socket extends EventEmitter {
    static OPEN = 1;
    readyState = 1;
    sent: Buffer[] = [];
    terminated = false;
    constructor(readonly url: string) {
      super(); sockets.push(this); queueMicrotask(() => this.emit("open"));
    }
    send(bytes: Buffer) { this.sent.push(Buffer.from(bytes)); }
    terminate() {
      if (this.terminated) return;
      this.terminated = true; this.readyState = 3; this.emit("close");
    }
  }
  return { WebSocket: Socket };
});
import { QQQrAuth, credentialCookie, parseMqttPacket, parseWechatStatus } from "./qq-auth.js";
import { QQMusicProvider } from "./qq.js";

const http = vi.fn<typeof fetch>();
const cleanup: Array<{ dispose(): void }> = [];
const image = "data:image/png;base64,YQ==";
const credentials = { str_musicid: "12345678901234", musickey: "music-key", openid: "open-id", refresh_token: "refresh" };
const qqQr = async () => ({ qrsig: "private-qr-signature", ptqrtoken: 123, img: image });
const noPoll = async (_credentials: QqPollCredentials) => { throw new Error("Unexpected QQ poll"); };
const json = (data: unknown) => Response.json({ code: 0, req_0: { code: 0, data } });
const appQr = () => json({ qrcodeID: "private-app-id", qrcode: image });
async function flush() { for (let n = 0; n < 24; n++) await Promise.resolve(); }
async function socketAt(index: number) {
  await flush();
  const socket = sockets[index];
  if (!socket) throw new Error("Socket was not created");
  return socket;
}
function auth(ttl?: number) { const value = new QQQrAuth(ttl); cleanup.push(value); return value; }
function provider() { const value = new QQMusicProvider("http://sidecar"); cleanup.push(value); return value; }
function mqttString(value: string) {
  const bytes = Buffer.from(value); return Buffer.concat([Buffer.from([bytes.length >> 8, bytes.length & 255]), bytes]);
}
function frame(header: number, body: Buffer) {
  const size: number[] = []; let n = body.length;
  do { const byte = n % 128; n = Math.floor(n / 128); size.push(byte | (n ? 128 : 0)); } while (n);
  return Buffer.concat([Buffer.from([header, ...size]), body]);
}
function publish(type: string, payload: unknown = {}) {
  const props = Buffer.concat([Buffer.from([0x26]), mqttString("type"), mqttString(type)]);
  return frame(0x30, Buffer.concat([mqttString("management.qrcode_login/private-app-id"), Buffer.from([props.length]), props, Buffer.from(JSON.stringify(payload))]));
}
const connack = Buffer.from([0x20, 3, 0, 0, 0]);
const suback = Buffer.from([0x90, 4, 0, 1, 0, 0]);
async function readyApp(value: QQQrAuth) {
  const pending = value.getQrCode("app", qqQr);
  const socket = await socketAt(sockets.length);
  socket.emit("message", connack, true); socket.emit("message", suback, true);
  return { qr: await pending, socket };
}
function loginEvent(id = "12345678901234") {
  return publish("cookies", { cookies: { qqmusic_uin: { value: `o${id}` }, qqmusic_key: { value: "one-time-token" } } });
}

beforeEach(() => {
  vi.useRealTimers(); sockets.length = 0; get.mockReset(); post.mockReset(); http.mockReset(); vi.stubGlobal("fetch", http);
});
afterEach(() => {
  for (const item of cleanup.splice(0)) item.dispose();
  vi.unstubAllGlobals(); vi.useRealTimers();
});

describe("QQ auth protocol decoding", () => {
  it("reads MQTT v5 reason codes after flags and before properties", () => {
    expect(parseMqttPacket(connack)).toEqual({ kind: "connack", reason: 0, server: undefined });
    const server = Buffer.concat([Buffer.from([0x1c]), mqttString("shard-2")]);
    expect(parseMqttPacket(frame(0x20, Buffer.concat([Buffer.from([0, 0x9c, server.length]), server]))))
      .toEqual({ kind: "connack", reason: 0x9c, server: "shard-2" });
    expect(parseMqttPacket(Buffer.from([0x90, 4, 0, 1, 0, 0x87])))
      .toEqual({ kind: "suback", packetId: 1, reasons: Buffer.from([0x87]) });
  });
  it.each([
    [0x20, 3, 0, 0], [0x20, 4, 0, 0, 1, 0x13],
    [0x20, 5, 0, 0, 2, 0x1c, 0], [0x20, 0xff, 0xff, 0xff, 0xff],
    [0x90, 3, 0, 1, 0], [0x20, 4, 0, 0, 1, 0xff],
  ])("rejects malformed packet %# without disclosing payload", (...bytes: number[]) => {
    expect(() => parseMqttPacket(Buffer.from(bytes))).toThrow(/invalid response/);
  });
  it("preserves a publish payload containing multi-byte remaining length", () => {
    const payload = { token: "x".repeat(200) };
    const result = parseMqttPacket(publish("cookies", payload));
    expect(result.kind).toBe("publish");
    if (result.kind !== "publish") throw new Error("Wrong event");
    expect(result.type).toBe("cookies"); expect(JSON.parse(result.payload.toString())).toEqual(payload);
  });
  it("distinguishes WeChat waiting, scan, success, expiry and rejection", () => {
    expect(parseWechatStatus("window.wx_errcode=408;window.wx_code='';")).toEqual({ status: "waiting" });
    expect(parseWechatStatus("window.wx_errcode = 404;")).toEqual({ status: "scanned" });
    expect(parseWechatStatus("window.wx_errcode=402;")).toEqual({ status: "expired" });
    expect(parseWechatStatus("window.wx_errcode=405;window.wx_code='auth-code';")).toEqual({ status: "confirmed", code: "auth-code" });
    for (const body of ["window.wx_errcode=403;", "window.wx_errcode=405;window.wx_code='';", "garbage", "window.wx_errcode=500;"]) {
      expect(() => parseWechatStatus(body)).toThrow();
    }
  });
  it("keeps music identity precision and validates cookie credentials", () => {
    const cookie = credentialCookie({ ...credentials, str_musicid: "123456789012345678" }, "wechat");
    expect(cookie).toContain("uin=123456789012345678");
    expect(cookie).toContain("qm_keyst=music-key"); expect(cookie).toContain("tmeLoginType=1");
    expect(cookie).toContain("psrf_wxopenid=open-id"); expect(cookie).toContain("refresh_token=refresh");
    expect(credentialCookie(credentials, "app")).toContain("tmeLoginType=6");
    for (const bad of [{ musicid: 123 }, { musickey: "secret" }, { ...credentials, musickey: "secret; injected=1" }]) {
      expect(() => credentialCookie(bad, "app")).toThrow(/invalid response/);
    }
  });
});

describe("opaque bounded QR sessions", () => {
  it("shares concurrent polling and consumes a successful result only once", async () => {
    const value = auth(); const qr = await value.getQrCode("qq", qqQr);
    expect(qr.key).not.toContain("private-qr-signature");
    const gate = Promise.withResolvers<{ status: "confirmed"; cookie: string }>();
    const poll = vi.fn(() => gate.promise);
    const first = value.checkQrCodeStatus(qr.key, poll); const second = value.checkQrCodeStatus(qr.key, poll);
    gate.resolve({ status: "confirmed", cookie: "uin=123; qqmusic_key=key" });
    expect(await Promise.all([first, second])).toEqual(["confirmed", "confirmed"]); expect(poll).toHaveBeenCalledTimes(1);
    expect(value.consumeCookie(qr.key)).toBe("uin=123; qqmusic_key=key");
    expect(value.consumeCookie(qr.key)).toBe("");
    expect(await value.checkQrCodeStatus(qr.key, noPoll)).toBe("confirmed");
  });
  it("expires retained successful sessions and rejects late poll completion", async () => {
    vi.useFakeTimers();
    const value = auth(100); const qr = await value.getQrCode("qq", qqQr);
    const gate = Promise.withResolvers<{ status: "confirmed"; cookie: string }>();
    const result = value.checkQrCodeStatus(qr.key, () => gate.promise);
    await vi.advanceTimersByTimeAsync(101); gate.resolve({ status: "confirmed", cookie: "late-secret" });
    expect(await result).toBe("expired"); expect(value.consumeCookie(qr.key)).toBe("");
    const next = await value.getQrCode("qq", qqQr);
    await value.checkQrCodeStatus(next.key, async () => ({ status: "confirmed", cookie: "good" }));
    await vi.advanceTimersByTimeAsync(101);
    expect(await value.checkQrCodeStatus(next.key, noPoll)).toBe("expired");
  });
  it("does not turn missing credentials or network exceptions into confirmation", async () => {
    const value = auth(); const qr = await value.getQrCode("qq", qqQr);
    await expect(value.checkQrCodeStatus(qr.key, async () => ({ status: "confirmed" }))).rejects.toThrow(/invalid response/);
    await expect(value.checkQrCodeStatus(qr.key, async () => { throw new Error("private-token"); })).rejects.toThrow(/^QQ Music login service unavailable or invalid response$/);
    expect(value.consumeCookie(qr.key)).toBe("");
  });
  it("polls WeChat through scan and code exchange before issuing credentials", async () => {
    http.mockResolvedValueOnce(new Response('<img src="/connect/qrcode/wx-uuid">'))
      .mockResolvedValueOnce(new Response(Buffer.from("qr")))
      .mockResolvedValueOnce(new Response("window.wx_errcode=404;"))
      .mockResolvedValueOnce(new Response("window.wx_errcode=405;window.wx_code='private-code';"))
      .mockResolvedValueOnce(json(credentials));
    const value = auth(); const qr = await value.getQrCode("wechat", qqQr);
    expect(qr.key).not.toContain("wx-uuid"); expect(value.consumeCookie(qr.key)).toBe("");
    expect(await value.checkQrCodeStatus(qr.key, noPoll)).toBe("scanned");
    expect(await value.checkQrCodeStatus(qr.key, noPoll)).toBe("confirmed");
    expect(value.consumeCookie(qr.key)).toContain("tmeLoginType=1");
    expect(await value.checkQrCodeStatus(qr.key, noPoll)).toBe("confirmed");
  });
  it("rejects WeChat exchange failures without exposing response secrets", async () => {
    http.mockResolvedValueOnce(new Response('uuid=wx-id"'))
      .mockResolvedValueOnce(new Response(Buffer.from("qr")))
      .mockResolvedValueOnce(new Response("window.wx_errcode=405;window.wx_code='private-code';"))
      .mockResolvedValueOnce(Response.json({ req_0: { code: 500, data: { token: "private-secret" } } }));
    const value = auth(); const qr = await value.getQrCode("wechat", qqQr);
    await expect(value.checkQrCodeStatus(qr.key, noPoll)).rejects.toThrow(/^QQ Music login service unavailable or invalid response$/);
    expect(value.consumeCookie(qr.key)).toBe("");
  });
});

describe("official-app MQTT login lifecycle", () => {
  it("follows CONNACK redirects and waits for a successful SUBACK", async () => {
    http.mockResolvedValueOnce(appQr()); const value = auth();
    let returned = false; const pending = value.getQrCode("app", qqQr).then(qr => { returned = true; return qr; });
    const first = await socketAt(0);
    const props = Buffer.concat([Buffer.from([0x1c]), mqttString("shard")]);
    first.emit("message", frame(0x20, Buffer.concat([Buffer.from([0, 0x9c, props.length]), props])), true);
    const second = await socketAt(1); expect(first.terminated).toBe(true); expect(second.url).toBe("wss://mu.y.qq.com/ws/handshake/shard");
    second.emit("message", connack.subarray(0, 2), true);
    second.emit("message", connack.subarray(2), true);
    await flush(); expect(returned).toBe(false);
    second.emit("message", suback, true);
    const qr = await pending; expect(await value.checkQrCodeStatus(qr.key, noPoll)).toBe("waiting");
    value.dispose(); expect(second.terminated).toBe(true);
  });
  it("rejects SUBACK denial instead of returning a dead QR", async () => {
    http.mockResolvedValueOnce(appQr()); const value = auth();
    const pending = value.getQrCode("app", qqQr); const rejected = expect(pending).rejects.toThrow(/invalid response/);
    const socket = await socketAt(0); socket.emit("message", connack, true);
    socket.emit("message", Buffer.from([0x90, 4, 0, 1, 0, 0x87]), true);
    await rejected; expect(socket.terminated).toBe(true);
  });
  it("processes coalesced events once and stops its socket after exchange", async () => {
    const gate = Promise.withResolvers<Response>();
    http.mockResolvedValueOnce(appQr()).mockImplementationOnce(() => gate.promise);
    const value = auth(); const { qr, socket } = await readyApp(value);
    socket.emit("message", publish("scanned"), true);
    expect(await value.checkQrCodeStatus(qr.key, noPoll)).toBe("scanned");
    socket.emit("message", Buffer.concat([loginEvent(), loginEvent()]), true);
    await flush(); expect(http).toHaveBeenCalledTimes(2); expect(value.consumeCookie(qr.key)).toBe("");
    gate.resolve(json(credentials)); await flush();
    expect(await value.checkQrCodeStatus(qr.key, noPoll)).toBe("confirmed");
    expect(value.consumeCookie(qr.key)).toContain("tmeLoginType=6");
    expect(socket.terminated).toBe(true);
    expect(await value.checkQrCodeStatus(qr.key, noPoll)).toBe("confirmed");
  });
  it("exchanges an int64 music ID without rounding or sending a JSON string", async () => {
    const id = "123456789012345678";
    http.mockResolvedValueOnce(appQr()).mockImplementationOnce(async (_url, init) => {
      const accepted = String(init?.body).includes(`"musicid":${id},`);
      return accepted ? json({ ...credentials, str_musicid: id }) : Response.json({ req_0: { code: 1 } });
    });
    const value = auth(); const { qr, socket } = await readyApp(value);
    socket.emit("message", loginEvent(id), true); await flush();
    expect(await value.checkQrCodeStatus(qr.key, noPoll)).toBe("confirmed");
    expect(value.consumeCookie(qr.key)).toContain(`qqmusic_uin=${id};`);
  });
  it.each(["canceled", "loginFailed", "disconnect", "exchange"])("surfaces %s as an error rather than expiry/success", async cause => {
    http.mockResolvedValueOnce(appQr()).mockResolvedValueOnce(Response.json({ req_0: { code: 1, data: { token: "secret" } } }));
    const value = auth(); const { qr, socket } = await readyApp(value);
    if (cause === "disconnect") socket.terminate();
    else socket.emit("message", cause === "exchange" ? loginEvent() : publish(cause), true);
    await flush();
    await expect(value.checkQrCodeStatus(qr.key, noPoll)).rejects.toThrow(/^QQ Music login service unavailable or invalid response$/);
    expect(value.consumeCookie(qr.key)).toBe("");
  });
  it("expires the socket and never resurrects an in-flight credential exchange", async () => {
    vi.useFakeTimers();
    const gate = Promise.withResolvers<Response>();
    http.mockResolvedValueOnce(appQr()).mockImplementationOnce(() => gate.promise);
    const value = auth(100); const { qr, socket } = await readyApp(value);
    socket.emit("message", loginEvent(), true);
    await vi.advanceTimersByTimeAsync(101); gate.resolve(json(credentials)); await flush();
    expect(socket.terminated).toBe(true); expect(await value.checkQrCodeStatus(qr.key, noPoll)).toBe("expired");
    expect(value.consumeCookie(qr.key)).toBe("");
  });
});

describe("QQ provider credential consumption", () => {
  it("keeps repeated confirmation without replacing a subsequent cookie", async () => {
    get.mockResolvedValue({ data: await qqQr() });
    post.mockResolvedValue({ data: { isOk: true, session: { cookie: "uin=123; qqmusic_key=old" } } });
    const value = provider(); const qr = await value.getQrCode();
    expect(value.getCookie()).toBe(""); expect(await value.checkQrCodeStatus(qr.key)).toBe("confirmed");
    expect(value.getCookie()).toBe("uin=123; qqmusic_key=old");
    value.setCookie("uin=456; qqmusic_key=new");
    expect(await value.checkQrCodeStatus(qr.key)).toBe("confirmed"); expect(value.getCookie()).toBe("uin=456; qqmusic_key=new");
  });
  it("does not apply pending login credentials after a manual account change", async () => {
    get.mockResolvedValue({ data: await qqQr() });
    const gate = Promise.withResolvers<{ data: { isOk: boolean; session: { cookie: string } } }>(); post.mockImplementation(() => gate.promise);
    const value = provider(); const qr = await value.getQrCode(); const status = value.checkQrCodeStatus(qr.key);
    value.setCookie("uin=456; qqmusic_key=new"); gate.resolve({ data: { isOk: true, session: { cookie: "obsolete" } } });
    expect(await status).toBe("expired"); expect(value.getCookie()).toBe("uin=456; qqmusic_key=new");
  });
  it.each(["wechat", "app"] as const)("supports authenticated playback and status for %s music IDs", async type => {
    const value = provider(); value.setCookie(credentialCookie(credentials, type));
    const loginType = type === "wechat" ? 1 : 6;
    post.mockImplementation(async (_url: string, body: { comm: { tmeLoginType: number; qq: string; authst: string }; req_0: { method: string; param: { songmid?: string[] } } }) => {
      if (body.comm.tmeLoginType !== loginType || body.comm.qq !== credentials.str_musicid || body.comm.authst !== credentials.musickey) {
        return { data: { code: 1000 } };
      }
      if (body.req_0.method === "CgiGetVkey") return { data: { code: 0, req_0: { code: 0, data: { sip: ["https://audio.qq.test/"],
        midurlinfo: body.req_0.param.songmid?.map(mid => ({ songmid: mid, purl: mid === "blocked" ? "" : `${mid}.mp3` })) } } } };
      return { data: { code: 0, req_0: { code: 0, data: { Info: { BaseInfo: { Name: "Music User", Avatar: "https://image.qq.test/a" } } } }, vip: { code: 0, data: { identity: { vip: 0 } } } } };
    });
    expect(await value.getSongUrl("song")).toMatchObject({ url: "https://audio.qq.test/song.mp3" });
    expect(await value.getPlayableSongIds(["song", "blocked"])).toEqual(new Set(["song"]));
    expect(await value.getAuthStatus()).toMatchObject({ loggedIn: true, nickname: "Music User" });
    post.mockResolvedValue({ data: { code: 1000 } });
    expect(await value.getAuthStatus()).toEqual({ loggedIn: false });
    expect(await value.getSongUrl("song")).toBeNull();
  });
});
