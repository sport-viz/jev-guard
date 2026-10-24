/**
 * Jev Guard extension for Pi (`pi-coding-agent`).
 *
 * Installed to `~/.pi/agent/extensions/jev-guard.ts` by `scripts/configure_settings.py`.
 * Delegates every `tool_call` event to `~/.claude/jev-guard/jev_guard/hook.py --host pi`.
 * Any failure on the way becomes "ask" (fail to ask): the user decides when the guard can't.
 */

import { spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";

const MAX_PROMPTS = 4;
const MAX_CHARS = 4000;
const HOOK_TIMEOUT_MS = 20_000;

interface GuardResult {
  decision: "allow" | "pass" | "ask" | "deny";
  reason?: string;
}

function extractText(content: unknown): string {
  if (typeof content === "string") return content.trim();
  if (Array.isArray(content)) {
    return content
      .filter((b): b is { type: string; text?: string } => typeof b === "object" && b !== null)
      .filter((b) => b.type === "text" && typeof b.text === "string")
      .map((b) => b.text!)
      .join("\n")
      .trim();
  }
  return "";
}

function recentUserRequest(sessionManager: any): string | undefined {
  try {
    const entries: any[] =
      sessionManager?.getBranch?.() ?? sessionManager?.getEntries?.() ?? [];
    const prompts: string[] = [];
    for (let i = entries.length - 1; i >= 0 && prompts.length < MAX_PROMPTS; i--) {
      const entry = entries[i];
      if (entry?.type !== "message" || entry?.message?.role !== "user") continue;
      const text = extractText(entry.message.content);
      if (text) prompts.push(text);
    }
    if (prompts.length === 0) return undefined;
    const joined = prompts.reverse().join("\n---\n");
    return joined.length > MAX_CHARS ? joined.slice(-MAX_CHARS) : joined;
  } catch {
    return undefined;
  }
}

function summarizeTarget(toolName: string, input: Record<string, unknown>): string {
  const raw =
    (typeof input.command === "string" && input.command) ||
    (typeof input.path === "string" && input.path) ||
    JSON.stringify(input);
  const singleLine = raw.replace(/\s+/g, " ").trim();
  return singleLine.length > 140 ? `${singleLine.slice(0, 140)}...` : singleLine;
}

function runGuardHook(payload: Record<string, unknown>): Promise<GuardResult> {
  const guardHome =
    process.env.JEV_GUARD_HOME || path.join(os.homedir(), ".claude", "jev-guard");
  const pythonBin = path.join(guardHome, ".venv", "bin", "python");
  const hookScript = path.join(guardHome, "jev_guard", "hook.py");

  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let settled = false;

    const finish = (result: GuardResult) => {
      if (!settled) {
        settled = true;
        resolve(result);
      }
    };

    const child = spawn(pythonBin, [hookScript, "--host", "pi"], {
      stdio: ["pipe", "pipe", "pipe"],
      env: process.env,
    });

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish({
        decision: "ask",
        reason: "Jev guard timed out after 20s; confirm manually.",
      });
    }, HOOK_TIMEOUT_MS);

    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", (err: Error) => {
      clearTimeout(timer);
      finish({
        decision: "ask",
        reason: `Jev guard unavailable (${err.message}); confirm manually.`,
      });
    });
    child.on("close", () => {
      clearTimeout(timer);
      const trimmed = stdout.trim();
      if (!trimmed) {
        finish({
          decision: "ask",
          reason: `Jev guard returned empty output${stderr ? ` (${stderr.trim()})` : ""}; confirm manually.`,
        });
        return;
      }
      try {
        const parsed = JSON.parse(trimmed) as GuardResult;
        if (parsed && typeof parsed.decision === "string") {
          finish(parsed);
          return;
        }
      } catch {
        // fall through to fail-to-ask
      }
      finish({
        decision: "ask",
        reason: "Jev guard returned invalid JSON; confirm manually.",
      });
    });

    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(payload));
  });
}

export default function jevGuardExtension(pi: any): void {
  pi.on("tool_call", async (event: any, ctx: any) => {
    const toolName = String(event?.toolName ?? "");
    const toolInput =
      event?.input && typeof event.input === "object" ? event.input : {};

    const result = await runGuardHook({
      host: "pi",
      cwd: ctx?.cwd ?? process.cwd(),
      tool_name: toolName,
      tool_input: toolInput,
      transcript_path: ctx?.sessionManager?.getSessionFile?.() ?? undefined,
      user_request: recentUserRequest(ctx?.sessionManager),
      session_id: ctx?.sessionManager?.getSessionId?.() ?? undefined,
      agent_type: "pi",
    });

    if (result.decision === "allow" || result.decision === "pass") {
      return undefined;
    }

    const reason = result.reason || `Jev guard flagged this ${toolName} call.`;
    if (result.decision === "deny") {
      if (ctx?.hasUI && typeof ctx?.ui?.notify === "function") {
        ctx.ui.notify(reason, "error");
      }
      return { block: true, reason };
    }

    // "ask": prompt the user when interactive UI is available; block in headless mode.
    if (!ctx?.hasUI || typeof ctx?.ui?.confirm !== "function") {
      return { block: true, reason: `${reason} (blocked in non-interactive mode)` };
    }
    const target = summarizeTarget(toolName, toolInput);
    const confirmed = await ctx.ui.confirm(
      "Jev Guard",
      `${reason}\n\nAllow ${toolName}: ${target}?`,
    );
    if (!confirmed) {
      return { block: true, reason };
    }
    return undefined;
  });
}
