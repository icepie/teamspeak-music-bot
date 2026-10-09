/// <reference lib="es2024.promise" />
/*
 * Protocol adapted from qmtui's LoginService.
 * MIT License
 * Copyright (c) 2026 Yuzuki
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
import { randomBytes } from "node:crypto";
import { WebSocket } from "ws";
import type { QrCodeResult } from "./provider.js";

export type QQLoginType = "qq" | "wechat" | "app";
export type QQQrStatus = "waiting" | "scanned" | "confirmed" | "expired";
export interface QqSidecarQr { img?: string; qrsig?: string; ptqrtoken?: string | number; }
export interface QqPollCredentials { qrsig: string; ptqrtoken: string; }
interface PollResult { status: QQQrStatus; cookie?: string; }
interface Session {
  type: QQLoginType;
  expiresAt: number;
  status: QQQrStatus;
  cookie?: string;
  consumed?: boolean;
  error?: Error;
  poll?: Promise<QQQrStatus>;
  id: string;
  qqToken?: string;
  controller: AbortController;
  socket?: WebSocket;
  cleanup: NodeJS.Timeout;
  heartbeat?: NodeJS.Timeout;
  exchanging?: boolean;
}
const MUSICU_URL = "https://u.y.qq.com/cgi-bin/musicu.fcg";
const TTL = 5 * 60_000;
const HEADERS = { "content-type": "application/json", "user-agent": "QQMusic 14090008(android 14)" };

function field(value: unknown, key: string): unknown {
  return value !== null && typeof value === "object" && key in value
    ? (value as Record<string, unknown>)[key] : undefined;
}
function text(value: unknown): string {
  return typeof value === "string" || (typeof value === "number" && Number.isSafeInteger(value)) ? String(value) : "";
}
function fail(): Error { return new Error("QQ Music login service unavailable or invalid response"); }
async function request(url: string, signal: AbortSignal, init: RequestInit = {}): Promise<Response> {
  try {
    const response = await fetch(url, { ...init, signal: AbortSignal.any([signal, AbortSignal.timeout(40_000)]) });
    if (!response.ok) throw fail();
    return response;
  } catch { throw fail(); }
}
async function musicu(method: string, param: Record<string, unknown>, signal: AbortSignal, type?: QQLoginType): Promise<unknown> {
  let body = JSON.stringify({
    comm: { ct: 11, cv: 14090008, ...(type ? { v: 14090008, chid: "10003505", tmeAppID: "qqmusic", tmeLoginType: type === "wechat" ? 1 : 6 } : {}) },
    req_0: { module: "music.login.LoginServer", method, param },
  });
  if (type === "app" && method === "Login") {
    const id = param.musicid;
    if (typeof id !== "string" || !/^\d{1,19}$/.test(id) || BigInt(id) > 9223372036854775807n) throw fail();
    // LoginServer expects an int64 JSON number; Number would round large IDs.
    body = body.replace(`"musicid":"${id}"`, `"musicid":${BigInt(id)}`);
  }
  const response = await request(MUSICU_URL, signal, { method: "POST", headers: HEADERS, body });
  const json: unknown = await response.json();
  const result = field(json, "req_0");
  if (field(result, "code") !== 0 || (field(json, "code") !== undefined && field(json, "code") !== 0)) throw fail();
  return field(result, "data");
}

/** LoginServer credentials must include both a music identity and music key. */
export function credentialCookie(data: unknown, type: QQLoginType): string {
  const id = text(field(data, "str_musicid")) || text(field(data, "musicid"));
  const key = text(field(data, "musickey"));
  if (!/^\d+$/.test(id) || !key) throw fail();
  const cookies: Record<string, string> = {
    musicid: id, uin: id, qqmusic_uin: id, qqmusic_key: key, qm_keyst: key,
    qqmusic_version: "17", qqmusic_miniversion: "70", tmeLoginType: type === "wechat" ? "1" : "6",
  };
  const names: Record<string, string> = {
    openid: type === "wechat" ? "psrf_wxopenid" : "openid",
    access_token: type === "wechat" ? "psrf_wx_access_token" : "access_token",
    unionid: type === "wechat" ? "psrf_wxunionid" : "unionid", refresh_token: "refresh_token", refresh_key: "refresh_key",
  };
  for (const [source, name] of Object.entries(names)) {
    const value = text(field(data, source));
    if (value) cookies[name] = value;
  }
  if (Object.values(cookies).some(value => /[;\r\n]/.test(value))) throw fail();
  return Object.entries(cookies).map(([name, value]) => `${name}=${value}`).join("; ");
}
export function parseWechatStatus(body: string): { status: QQQrStatus; code?: string } {
  const code = /window\.wx_errcode\s*=\s*(\d+)/.exec(body)?.[1];
  switch (code) {
    case "408": return { status: "waiting" };
    case "404": return { status: "scanned" };
    case "402": return { status: "expired" };
    case "405": {
      const credential = /window\.wx_code\s*=\s*['"]([^'"]+)['"]/.exec(body)?.[1];
      if (!credential) throw fail();
      return { status: "confirmed", code: credential };
    }
    case "403": throw new Error("WeChat login was canceled");
    default: throw fail();
  }
}

// MQTT v5 codec: all reads are bounded to the current packet/property section.
class Reader {
  offset = 0;
  constructor(readonly bytes: Buffer) {}
  byte(): number { if (this.offset >= this.bytes.length) throw fail(); return this.bytes[this.offset++]; }
  uint16(): number { return (this.byte() << 8) | this.byte(); }
  vbi(): number {
    let value = 0;
    for (let n = 0; n < 4; n++) { const b = this.byte(); value += (b & 127) * 128 ** n; if (!(b & 128)) return value; }
    throw fail();
  }
  take(length: number): Buffer {
    if (length < 0 || this.offset + length > this.bytes.length) throw fail();
    const bytes = this.bytes.subarray(this.offset, this.offset + length); this.offset += length; return bytes;
  }
  string(): string { return this.take(this.uint16()).toString("utf8"); }
}
function vbi(value: number): Buffer {
  const bytes: number[] = [];
  do { const digit = value % 128; value = Math.floor(value / 128); bytes.push(digit | (value ? 128 : 0)); } while (value);
  return Buffer.from(bytes);
}
function mqttString(value: string): Buffer {
  const bytes = Buffer.from(value); if (bytes.length > 65535) throw fail();
  return Buffer.concat([Buffer.from([bytes.length >> 8, bytes.length & 255]), bytes]);
}
function userProperty(key: string, value: string): Buffer { return Buffer.concat([Buffer.from([0x26]), mqttString(key), mqttString(value)]); }
function packet(header: number, ...parts: Buffer[]): Buffer {
  const body = Buffer.concat(parts); return Buffer.concat([Buffer.from([header]), vbi(body.length), body]);
}
function properties(reader: Reader): { server?: string; type?: string } {
  const props = new Reader(reader.take(reader.vbi()));
  const result: { server?: string; type?: string } = {};
  while (props.offset < props.bytes.length) {
    const property = props.byte();
    switch (property) {
      case 0x1c: result.server = props.string(); break;
      case 0x26: { const key = props.string(); const value = props.string(); if (key === "type") result.type = value; break; }
      case 0x01: case 0x17: case 0x19: case 0x24: case 0x25: case 0x28: case 0x29: case 0x2a: props.take(1); break;
      case 0x13: case 0x21: case 0x22: case 0x23: props.take(2); break;
      case 0x02: case 0x11: case 0x18: case 0x27: props.take(4); break;
      case 0x0b: props.vbi(); break;
      case 0x09: case 0x16: props.take(props.uint16()); break;
      case 0x03: case 0x08: case 0x12: case 0x15: case 0x1a: case 0x1f: props.string(); break;
      default: throw fail();
    }
  }
  return result;
}
export type MqttEvent =
  | { kind: "connack"; reason: number; server?: string }
  | { kind: "suback"; packetId: number; reasons: Buffer }
  | { kind: "publish"; type?: string; topic: string; payload: Buffer; packetId?: number }
  | { kind: "ping" };
export function parseMqttPacket(bytes: Buffer): MqttEvent {
  const reader = new Reader(bytes);
  const header = reader.byte();
  const length = reader.vbi();
  if (length !== bytes.length - reader.offset) throw fail();
  switch (header >> 4) {
    case 2: {
      if (header !== 0x20) throw fail();
      reader.byte(); const reason = reader.byte(); const { server } = properties(reader);
      if (reader.offset !== bytes.length) throw fail();
      return { kind: "connack", reason, server };
    }
    case 9: {
      if (header !== 0x90) throw fail();
      const packetId = reader.uint16(); properties(reader);
      const reasons = reader.take(bytes.length - reader.offset); if (!reasons.length) throw fail();
      return { kind: "suback", packetId, reasons };
    }
    case 3: {
      const qos = (header >> 1) & 3; if (qos > 1) throw fail();
      const topic = reader.string(); const packetId = qos ? reader.uint16() : undefined;
      const { type } = properties(reader);
      return { kind: "publish", topic, type, packetId, payload: reader.take(bytes.length - reader.offset) };
    }
    case 13: if (header === 0xd0 && !length) return { kind: "ping" }; throw fail();
    default: throw fail();
  }
}

export class QQQrAuth {
  private readonly sessions = new Map<string, Session>();
  constructor(private readonly ttlMs = TTL) {}

  async getQrCode(type: QQLoginType, fetchQq: () => Promise<QqSidecarQr>): Promise<QrCodeResult> {
    if (type !== "qq" && type !== "wechat" && type !== "app") throw fail();
    if (this.sessions.size >= 64) throw new Error("Too many pending QQ Music logins");
    const key = randomBytes(24).toString("base64url");
    const session: Session = {
      type, status: "waiting", expiresAt: Date.now() + this.ttlMs, id: "", controller: new AbortController(),
      cleanup: setTimeout(() => this.remove(key), this.ttlMs),
    };
    session.cleanup.unref(); this.sessions.set(key, session);
    try {
      let image: string;
      if (type === "qq") {
        const qr = await fetchQq();
        if (!qr.qrsig || qr.ptqrtoken === undefined || !qr.img) throw fail();
        session.id = qr.qrsig; session.qqToken = String(qr.ptqrtoken); image = qr.img;
      } else if (type === "wechat") {
        const params = new URLSearchParams({ appid: "wx48db31d50e334801", redirect_uri: "https://y.qq.com/portal/wx_redirect.html?login_type=2&surl=https://y.qq.com/", response_type: "code", scope: "snsapi_login", state: "STATE", href: "https://y.qq.com/mediastyle/music_v17/src/css/popup_wechat.css#wechat_redirect" });
        const response = await request(`https://open.weixin.qq.com/connect/qrconnect?${params}`, session.controller.signal);
        const html = await response.text();
        const uuid = /uuid=([a-zA-Z0-9_-]+)/.exec(html)?.[1] ?? /\/connect\/qrcode\/([a-zA-Z0-9_-]+)/.exec(html)?.[1];
        if (!uuid) throw fail(); session.id = uuid;
        const qr = await request(`https://open.weixin.qq.com/connect/qrcode/${uuid}`, session.controller.signal, { headers: { referer: "https://open.weixin.qq.com/connect/qrconnect" } });
        const bytes = Buffer.from(await qr.arrayBuffer()); if (!bytes.length) throw fail();
        image = `data:image/jpeg;base64,${bytes.toString("base64")}`;
      } else {
        const data = await musicu("CreateQRCode", { tmeAppID: "qqmusic", ct: 11, cv: 14090008 }, session.controller.signal);
        session.id = text(field(data, "qrcodeID")); image = text(field(data, "qrcode"));
        if (!session.id || !/^data:image\/(png|jpe?g);base64,[A-Za-z0-9+/=]+$/.test(image)) throw fail();
        await this.connectApp(session);
      }
      if (!this.active(session) || session.error) throw fail();
      return { qrUrl: "", qrImg: image, key };
    } catch { this.remove(key); throw fail(); }
  }

  async checkQrCodeStatus(key: string, pollQq: (credentials: QqPollCredentials) => Promise<PollResult>): Promise<QQQrStatus> {
    const session = this.sessions.get(key);
    if (!session || Date.now() >= session.expiresAt) { this.remove(key); return "expired"; }
    if (session.error) throw session.error;
    if (session.status === "confirmed" || session.status === "expired") return session.status;
    if (session.type === "app") return session.status;
    if (!session.poll) {
      session.poll = this.poll(session, pollQq).finally(() => { session.poll = undefined; });
    }
    return session.poll;
  }

  /** A replayed successful QR remains confirmed but cannot overwrite a newer login. */
  consumeCookie(key: string): string {
    const session = this.sessions.get(key);
    if (!session || !this.active(session) || session.status !== "confirmed" || session.consumed) return "";
    session.consumed = true;
    const cookie = session.cookie ?? "";
    session.cookie = undefined;
    return cookie;
  }
  supersede(): void {
    for (const [key, session] of this.sessions) {
      if (session.status !== "confirmed") this.remove(key);
      else { session.consumed = true; session.cookie = undefined; }
    }
  }
  dispose(): void { for (const key of this.sessions.keys()) this.remove(key); }
  private active(session: Session): boolean { return !session.controller.signal.aborted && Date.now() < session.expiresAt; }
  private stop(session: Session): void {
    clearInterval(session.heartbeat);
    session.socket?.terminate(); session.socket = undefined;
  }
  private remove(key: string): void {
    const session = this.sessions.get(key); if (!session) return;
    this.sessions.delete(key); clearTimeout(session.cleanup); session.controller.abort(); this.stop(session);
    session.cookie = undefined;
  }
  private async poll(session: Session, pollQq: (credentials: QqPollCredentials) => Promise<PollResult>): Promise<QQQrStatus> {
    try {
      let result: PollResult;
      if (session.type === "qq") {
        result = await pollQq({ qrsig: session.id, ptqrtoken: session.qqToken! });
      } else {
        const response = await request(`https://lp.open.weixin.qq.com/connect/l/qrconnect?uuid=${encodeURIComponent(session.id)}&_=${Date.now()}`, session.controller.signal, { headers: { referer: "https://open.weixin.qq.com/" } });
        const parsed = parseWechatStatus(await response.text());
        result = { status: parsed.status };
        if (parsed.status === "confirmed") {
          const data = await musicu("Login", { code: parsed.code, strAppid: "wx48db31d50e334801" }, session.controller.signal, "wechat");
          result.cookie = credentialCookie(data, "wechat");
        }
      }
      if (!this.active(session)) return "expired";
      if (result.status === "confirmed" && !result.cookie) throw fail();
      session.status = result.status; session.cookie = result.cookie;
      return session.status;
    } catch {
      if (!this.active(session)) return "expired";
      throw fail();
    }
  }

  private async connectApp(session: Session): Promise<void> {
    let path = "/ws/handshake";
    for (let redirects = 0; redirects <= 3; redirects++) {
      const result = await this.connectOnce(session, path);
      if (!result) return;
      if (redirects === 3 || result.length > 512 || /[?#\\\u0000-\u0020]/.test(result)) throw fail();
      path += `/${result}`;
    }
    throw fail();
  }
  private connectOnce(session: Session, path: string): Promise<string | undefined> {
    const { promise, resolve, reject } = Promise.withResolvers<string | undefined>();
    const ws = new WebSocket(`wss://mu.y.qq.com${path}`, "mqtt", {
      handshakeTimeout: 15_000, maxPayload: 1024 * 1024,
      headers: { Origin: "https://y.qq.com", Referer: "https://y.qq.com/", "User-Agent": "Mozilla/5.0 Chrome/128 Safari/537.36" },
    });
    session.socket = ws;
    let stage: "connect" | "subscribe" | "ready" | "closed" = "connect";
    let pending: Buffer = Buffer.alloc(0);
    const timer = setTimeout(() => failure(), 15_000); timer.unref();
    const failure = () => {
      if (stage === "closed") return;
      const wasReady = stage === "ready"; stage = "closed"; clearTimeout(timer); clearInterval(session.heartbeat);
      if (this.active(session) && session.status !== "confirmed" && session.status !== "expired") session.error = fail();
      ws.terminate(); if (!wasReady) reject(fail());
    };
    ws.on("error", failure);
    ws.on("close", failure);
    ws.on("open", () => {
      const props = Buffer.concat([
        Buffer.from([0x15]), mqttString("pass"), userProperty("tmeAppID", "qqmusic"), userProperty("business", "management"),
        userProperty("hashTag", session.id), userProperty("clientTag", "management.user"), userProperty("userID", session.id),
      ]);
      ws.send(packet(0x10, mqttString("MQTT"), Buffer.from([5, 2, 0, 45]), vbi(props.length), props, mqttString(`${Date.now()}${randomBytes(4).toString("hex")}`)));
    });
    ws.on("message", (raw, binary) => {
      try {
        if (!binary || stage === "closed") throw fail();
        const bytes = Array.isArray(raw) ? Buffer.concat(raw) : Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
        pending = pending.length ? Buffer.concat([pending, bytes]) : bytes;
        if (pending.length > 1024 * 1024) throw fail();
        while (pending.length >= 2) {
          let size = 0; let end = 1; let complete = false;
          for (let n = 0; n < 4 && end < pending.length; n++) {
            const b = pending[end++]; size += (b & 127) * 128 ** n;
            if (!(b & 128)) { complete = true; break; }
            if (n === 3) throw fail();
          }
          if (!complete) return;
          if (size > 1024 * 1024) throw fail();
          if (pending.length < end + size) return;
          const event = parseMqttPacket(pending.subarray(0, end + size)); pending = pending.subarray(end + size);
          if (stage === "connect") {
            if (event.kind !== "connack") throw fail();
            if (event.reason === 0x9c || event.reason === 0x9d) {
              if (!event.server) throw fail();
              stage = "closed"; clearTimeout(timer); ws.terminate(); resolve(event.server); return;
            }
            if (event.reason !== 0) throw fail();
            stage = "subscribe";
            const props = Buffer.concat([userProperty("authorization", "tmelogin"), userProperty("pubsub", "unicast")]);
            ws.send(packet(0x82, Buffer.from([0, 1]), vbi(props.length), props, mqttString(`management.qrcode_login/${session.id}`), Buffer.from([0])));
          } else if (stage === "subscribe") {
            if (event.kind !== "suback" || event.packetId !== 1 || event.reasons.length !== 1 || event.reasons[0] > 2) throw fail();
            stage = "ready"; clearTimeout(timer);
            session.heartbeat = setInterval(() => { if (ws.readyState === WebSocket.OPEN) ws.send(Buffer.from([0xc0, 0])); }, 25_000);
            session.heartbeat.unref(); resolve(undefined);
          } else if (event.kind === "publish") {
            if (event.topic !== `management.qrcode_login/${session.id}`) throw fail();
            if (event.packetId) ws.send(packet(0x40, Buffer.from([event.packetId >> 8, event.packetId & 255])));
            void this.appEvent(session, event);
          } else if (event.kind !== "ping") throw fail();
        }
      } catch { failure(); }
    });
    return promise;
  }
  private async appEvent(session: Session, event: Extract<MqttEvent, { kind: "publish" }>): Promise<void> {
    if (!this.active(session) || session.error || session.status === "confirmed" || session.status === "expired") return;
    switch (event.type) {
      case "scanned": session.status = "scanned"; return;
      case "timeout": session.status = "expired"; this.stop(session); return;
      case "canceled": case "loginFailed": session.error = fail(); this.stop(session); return;
      case "cookies": break;
      default: return;
    }
    if (session.exchanging) return;
    session.exchanging = true;
    try {
      const json: unknown = JSON.parse(event.payload.toString("utf8"));
      const cookies = field(json, "cookies");
      const id = text(field(field(cookies, "qqmusic_uin"), "value")).replace(/^o+/, "");
      const token = text(field(field(cookies, "qqmusic_key"), "value"));
      if (!/^\d+$/.test(id) || !token) throw fail();
      const data = await musicu("Login", { musicid: id, qrCodeID: session.id, token }, session.controller.signal, "app");
      const cookie = credentialCookie(data, "app");
      if (this.active(session) && !session.error && !["confirmed", "expired"].includes(session.status)) {
        session.cookie = cookie; session.status = "confirmed";
      }
    } catch { if (this.active(session)) session.error = fail(); }
    finally { this.stop(session); }
  }
}
