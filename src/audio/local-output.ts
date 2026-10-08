import { spawn, type ChildProcess } from "node:child_process";
import type { Writable } from "node:stream";
import type { Logger } from "../logger.js";

/**
 * Sends the player's already-volume-adjusted PCM frames to the machine's
 * default PipeWire/PulseAudio sink. The process runs as the service user, so
 * the office speaker is the host's normal desktop audio output.
 */
export class LocalAudioOutput {
  private process: ChildProcess | null = null;
  private readonly command: string;
  private readonly logger: Logger;

  constructor(logger: Logger, command = process.env.TSMUSIC_AUDIO_PLAYER || "pw-play") {
    this.logger = logger;
    this.command = command;
  }

  start(): void {
    if (this.process) return;
    const child = spawn(
      this.command,
      [
        "--rate", "48000",
        "--channels", "2",
        "--format", "s16",
        "--media-role", "Music",
        "-",
      ],
      { stdio: ["pipe", "ignore", "pipe"] },
    );
    this.process = child;
    child.stderr?.on("data", (chunk: Buffer) => {
      this.logger.warn({ error: chunk.toString("utf8").trim() }, "Local audio output error");
    });
    child.once("error", (err) => {
      if (this.process === child) this.process = null;
      this.logger.error({ err, command: this.command }, "Failed to start local audio output");
    });
    child.once("exit", (code, signal) => {
      if (this.process === child) this.process = null;
      if (code !== 0 && signal === null) {
        this.logger.warn({ code, command: this.command }, "Local audio output exited");
      }
    });
  }

  write(frame: Buffer): void {
    const stdin = this.process?.stdin as Writable | undefined;
    if (!stdin || stdin.destroyed || !stdin.writable) return;
    // A 20 ms PCM frame is small enough for PipeWire's pipe. If the child is
    // briefly back-pressured, dropping one frame is preferable to growing an
    // unbounded queue and making the UI controls lag behind audible playback.
    stdin.write(frame);
  }

  stop(): void {
    const child = this.process;
    this.process = null;
    if (!child) return;
    child.stdin?.destroy();
    child.kill();
  }
}
