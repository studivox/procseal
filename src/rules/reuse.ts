import type { SafeLabel } from '../core/label.js';
import type { Pm2ProcessSnapshot } from '../core/pm2-types.js';
import { redactedPlaceholder } from '../core/redaction.js';
import { createFinding, type Finding } from '../core/types.js';

/**
 * PS004: cross-application sensitive-value reuse detection.
 *
 * Pure and side-effect-free: makes no I/O, mutates no input, and never
 * reads, returns, or retains a raw value. Every comparison goes through
 * `ObservedValue.equals()` (full-HMAC equality; see
 * `core/observed-value.ts` and `core/fingerprint.ts`) against values that
 * have already been marked `reuseCandidate` at the PM2 adapter boundary
 * (see `core/reuse-candidate-policy.ts`) — this function itself makes no
 * key-name or length decision, it only clusters and compares booleans and
 * opaque values it is handed.
 *
 * Compares `selected`'s PS004-eligible environment variables against
 * every *other PM2 application* in `allProcesses`. Only eligible-vs-
 * eligible pairs are ever compared: a long value under a non-credential-
 * looking key on either side is never treated as a PS004 match, even if
 * it happens to equal an eligible value elsewhere — see "Detect reuse
 * even when the same value appears under different sensitive variable
 * names" in the project's requirements, which is about *sensitive* names
 * on both sides, not any name.
 *
 * ## Application identity, not process records
 *
 * PM2 cluster mode runs one application as several process records (one
 * per worker), all sharing the same `safeName`. PS004 reuse is defined in
 * terms of distinct *applications*, never distinct *records*: "other
 * applications" is built by grouping every process in `allProcesses` by
 * `safeName` — never by `safeProcessId`, which is unique per record, not
 * per application.
 *
 * - A process whose `safeName` equals `selected.safeName` belongs to the
 *   *same* application as `selected` (a different cluster worker of it,
 *   most commonly) and is never counted as "another" application, however
 *   many such records exist. Four workers of the selected application
 *   sharing an eligible value with `selected` itself must never register
 *   as four — or even one — reused-elsewhere match; see "Repeated values
 *   inside only one application must not trigger PS004."
 * - Four cluster workers of one genuinely different application, all
 *   sharing `safeName`, still count as exactly **one** other application,
 *   never four.
 * - A process whose `safeName` is the redaction placeholder (its raw PM2
 *   name failed `SafeLabel` validation) is excluded entirely from the
 *   "other applications" grouping. `[REDACTED]` is not a real, shared
 *   application identity: two *different* unnamed-or-hostile-named
 *   processes would otherwise be silently merged into "one" application
 *   named `[REDACTED]` (undercounting), or a match against either would
 *   be misattributed to a fabricated shared identity. This is a
 *   deliberate, documented false-negative boundary — a reused value held
 *   only by applications with unsafe/unattributable names is never
 *   reported — see docs/THREAT_MODEL.md.
 *
 * Every environment variable also carries its own eligibility
 * (`reuseCandidate`), which is `false` whenever its own name failed
 * validation (see `core/pm2-types.ts`) — an invalid variable name is
 * never a candidate on either side, so a finding's `variable` is always a
 * genuine, safe, displayable name.
 *
 * ## Clustering and deduplication
 *
 * `selected`'s eligible variables are first partitioned into equivalence
 * classes ("clusters") using `ObservedValue.equals()` — so if `selected`
 * itself declares the same eligible value under two different names (e.g.
 * `API_KEY` and `CLIENT_SECRET` holding an identical value), that is one
 * cluster, not two, and is never reported purely for that — see "Repeated
 * values inside only one application must not trigger PS004." Each
 * cluster is then checked against every other *application*'s eligible
 * variables; a cluster produces a finding only when at least one other,
 * distinct application also holds an equal eligible value.
 *
 * This guarantees exactly one PS004 finding per distinct reused value in
 * `selected`, regardless of how many variable names it appears under
 * within `selected` or how many cluster workers either side runs (folded
 * into `reusedInApplicationCount` instead) — never a finding explosion
 * from pairwise name or worker combinations, and never two findings for
 * what is actually the same underlying value.
 *
 * ## Finding details
 *
 * - `variable`: `selected`'s variable name for this cluster. If the
 *   cluster has more than one name (the same value declared under
 *   multiple names within `selected`), the alphabetically-first name is
 *   used — deterministic, and independent of PM2's own object-key
 *   iteration order.
 * - `reusedInApplicationCount`: the number of *other, distinct
 *   applications* (not including `selected`'s own application, and never
 *   counting cluster workers of the same application separately) found to
 *   hold an equal eligible value, as a plain decimal string — a safe
 *   numeric count, not raw process or application names. Other
 *   applications' names are deliberately not enumerated here, so finding
 *   size stays bounded and deterministic regardless of fleet size;
 *   `AuditSubject.process` already identifies the selected application,
 *   and an operator can re-run with `--process <other-name>` to inspect a
 *   specific other application directly.
 *
 * ## Ordering
 *
 * Returned findings are sorted by `variable` (ordinal string comparison,
 * ascending) — deterministic, independent of PM2's own array order,
 * object-key iteration order, or how many cluster-worker records each
 * application happens to have, and stable across repeated runs against an
 * unchanged snapshot.
 */
export function evaluateReuseRule(
  selected: Pm2ProcessSnapshot,
  allProcesses: readonly Pm2ProcessSnapshot[],
): readonly Finding[] {
  const redacted = redactedPlaceholder();

  // `v.name !== redacted` is defense in depth, not the primary
  // enforcement: `src/adapters/pm2.ts` already never sets
  // `reuseCandidate: true` for a variable whose key failed validation, so
  // in normal operation this check is redundant with that guarantee. It
  // is kept here anyway, consistent with this project's layered-defense
  // pattern elsewhere (e.g. `core/output-safety.ts` re-validating a
  // `SafeLabel` at the final boundary rather than trusting the type
  // alone) — a caller that assembles a `Pm2ProcessSnapshot` by some other
  // means and mismarks a redacted-name variable as a candidate still
  // cannot produce a finding that references `[REDACTED]` as if it were
  // a real variable name.
  const selectedCandidates = selected.environmentVariables.filter(
    (v) => v.reuseCandidate && v.name !== redacted,
  );

  // Group every OTHER application's process records by safe application
  // name. Records belonging to the selected application itself (any
  // record sharing `selected.safeName`, i.e. another cluster worker of
  // it) and records with an unsafe/unattributable name are excluded from
  // this grouping entirely — see the doc comment above.
  const otherApplications = new Map<SafeLabel, Pm2ProcessSnapshot[]>();
  for (const process of allProcesses) {
    if (process.safeName === selected.safeName) {
      continue;
    }
    if (process.safeName === redacted) {
      continue;
    }
    const existing = otherApplications.get(process.safeName);
    if (existing) {
      existing.push(process);
    } else {
      otherApplications.set(process.safeName, [process]);
    }
  }

  interface Cluster {
    readonly representative: Pm2ProcessSnapshot['environmentVariables'][number]['value'];
    readonly names: SafeLabel[];
  }

  const clusters: Cluster[] = [];
  for (const candidate of selectedCandidates) {
    const existing = clusters.find((cluster) => cluster.representative.equals(candidate.value));
    if (existing) {
      if (!existing.names.includes(candidate.name)) {
        existing.names.push(candidate.name);
      }
      continue;
    }
    clusters.push({ representative: candidate.value, names: [candidate.name] });
  }

  const results: { readonly variable: SafeLabel; readonly reusedInApplicationCount: number }[] = [];

  for (const cluster of clusters) {
    let matchingApplicationCount = 0;
    for (const records of otherApplications.values()) {
      const applicationHasMatch = records.some((process) =>
        process.environmentVariables.some(
          (v) => v.reuseCandidate && v.name !== redacted && v.value.equals(cluster.representative),
        ),
      );
      if (applicationHasMatch) {
        matchingApplicationCount += 1;
      }
    }

    if (matchingApplicationCount === 0) {
      continue;
    }

    const variable = [...cluster.names].sort()[0]!;
    results.push({ variable, reusedInApplicationCount: matchingApplicationCount });
  }

  results.sort((a, b) => (a.variable < b.variable ? -1 : a.variable > b.variable ? 1 : 0));

  return results.map((result) =>
    createFinding({
      ruleId: 'PS004',
      severity: 'critical',
      details: {
        variable: result.variable,
        reusedInApplicationCount: String(result.reusedInApplicationCount),
      },
    }),
  );
}
