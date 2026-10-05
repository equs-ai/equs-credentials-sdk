import { readFileSync } from "node:fs";
import { resolve } from "node:path";

// Written by `cargo run -p equs-test-fixtures --bin fixture_gen` in pretest.
// Never committed: see .gitignore.
const path = process.env.EQUS_FIXTURE_BUNDLE ?? resolve(__dirname, "fixtures.generated.json");

let cached: Record<string, unknown> | undefined;

export function bundle(): Record<string, unknown> {
  if (!cached) {
    try {
      cached = JSON.parse(readFileSync(path, "utf8"));
    } catch (cause) {
      throw new Error(
        `fixture bundle missing at ${path} — run: cargo run -p equs-test-fixtures --bin fixture_gen -- --out ${path}`,
        { cause },
      );
    }
  }
  return cached;
}

export function token(name: string): string {
  const value = bundle()[name];
  if (typeof value !== "string") throw new Error(`fixture ${name} is not a token`);
  return value;
}
