import type { SafeLabel } from '../core/label.js';
import type { Pm2ProcessSnapshot } from '../core/pm2-types.js';
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
 * every *other* process in `allProcesses` (matched by `safeProcessId`,
 * which is unique within one snapshot — never by object identity, so this
 * function works correctly even against a snapshot assembled by a test
 * fixture rather than the real adapter). Only eligible-vs-eligible pairs
 * are ever compared: a long value under a non-credential-looking key on
 * either side is never treated as a PS004 match, even if it happens to
 * equal an eligible value elsewhere — see "Detect reuse even when the
 * same value appears under different sensitive variable names" in the
 * project's requirements, which is about *sensitive* names on both sides,
 * not any name.
 *
 * ## Clustering and deduplication
 *
 * `selected`'s eligible variables are first partitioned into equivalence
 * classes ("clusters") using `ObservedValue.equals()` — so if `selected`
 * itself declares the same eligible value under two different names (e.g.
 * `API_KEY` and `CLIENT_SECRET` holding an identical value), that is one
 * cluster, not two, and is never reported purely for that — see "Repeated
 * values inside only one application must not trigger PS004." Each
 * cluster is then checked against every other process's eligible
 * variables; a cluster produces a finding only when at least one other,
 * distinct process also holds an equal eligible value.
 *
 * This guarantees exactly one PS004 finding per distinct reused value in
 * `selected`, regardless of how many variable names it appears under
 * within `selected` or how many other processes also hold it (folded into
 * `reusedInProcessCount` instead) — never a finding explosion from
 * pairwise name combinations, and never two findings for what is actually
 * the same underlying value.
 *
 * ## Finding details
 *
 * - `variable`: `selected`'s variable name for this cluster. If the
 *   cluster has more than one name (the same value declared under
 *   multiple names within `selected`), the alphabetically-first name is
 *   used — deterministic, and independent of PM2's own object-key
 *   iteration order.
 * - `reusedInProcessCount`: the number of *other* distinct processes (not
 *   including `selected`) found to hold an equal eligible value, as a
 *   plain decimal string — a safe numeric count, not raw process names.
 *   Other processes' names are deliberately not enumerated here, so
 *   finding size stays bounded and deterministic regardless of fleet
 *   size; `AuditSubject.process` already identifies the selected process,
 *   and an operator can re-run with `--process <other-name>` to inspect a
 *   specific other process directly.
 *
 * ## Ordering
 *
 * Returned findings are sorted by `variable` (ordinal string comparison,
 * ascending) — deterministic, independent of PM2's own array order or
 * object-key iteration order, and stable across repeated runs against an
 * unchanged snapshot.
 */
export function evaluateReuseRule(
  selected: Pm2ProcessSnapshot,
  allProcesses: readonly Pm2ProcessSnapshot[],
): readonly Finding[] {
  const selectedCandidates = selected.environmentVariables.filter((v) => v.reuseCandidate);
  const otherProcesses = allProcesses.filter((p) => p.safeProcessId !== selected.safeProcessId);

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

  const results: { readonly variable: SafeLabel; readonly reusedInProcessCount: number }[] = [];

  for (const cluster of clusters) {
    let matchingOtherProcessCount = 0;
    for (const process of otherProcesses) {
      const hasMatch = process.environmentVariables.some(
        (v) => v.reuseCandidate && v.value.equals(cluster.representative),
      );
      if (hasMatch) {
        matchingOtherProcessCount += 1;
      }
    }

    if (matchingOtherProcessCount === 0) {
      continue;
    }

    const variable = [...cluster.names].sort()[0]!;
    results.push({ variable, reusedInProcessCount: matchingOtherProcessCount });
  }

  results.sort((a, b) => (a.variable < b.variable ? -1 : a.variable > b.variable ? 1 : 0));

  return results.map((result) =>
    createFinding({
      ruleId: 'PS004',
      severity: 'critical',
      details: {
        variable: result.variable,
        reusedInProcessCount: String(result.reusedInProcessCount),
      },
    }),
  );
}
