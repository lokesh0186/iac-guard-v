import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";

async function main(): Promise<void> {
  const deepsecRoot = process.argv[2];
  if (!deepsecRoot) {
    throw new Error("usage: deepsec_probe.ts DEEPSEC_CHECKOUT");
  }

  const evidenceRoot = dirname(fileURLToPath(import.meta.url));
  const matcherModule = resolve(
    deepsecRoot,
    "packages/scanner/src/matchers/k8s-privileged-workload.ts",
  );
  const { k8sPrivilegedWorkloadMatcher } = await import(pathToFileURL(matcherModule).href);

  const cases = [
    ["block_privileged", "block-privileged.yaml"],
    ["inline_privileged", "inline-privileged.yaml"],
    ["list_privileged", "list-privileged.yaml"],
    ["windows_hostprocess", "windows-hostprocess.yaml"],
  ] as const;

  const results = cases.map(([id, file]) => {
    const content = readFileSync(resolve(evidenceRoot, "fixtures", file), "utf8");
    const matches = k8sPrivilegedWorkloadMatcher.match(content, `fixtures/${file}`);
    return {
      id,
      fixture: `fixtures/${file}`,
      fixture_sha256: createHash("sha256").update(content).digest("hex"),
      matches: matches.map((match: { matchedPattern: string; lineNumbers: number[] }) => ({
        pattern: match.matchedPattern,
        line_numbers: match.lineNumbers,
      })),
    };
  });

  console.log(
    JSON.stringify(
      {
        repository: "vercel-labs/deepsec",
        pull_request: 112,
        base_sha: "97ebd04b455a492dfd5b9ad86f2dd9cf8b05fa04",
        head_sha: "783195c4b2a1da94c23f5cacf55114a190c2032f",
        matcher: "k8s-privileged-workload",
        results,
      },
      null,
      2,
    ),
  );
}

void main();
