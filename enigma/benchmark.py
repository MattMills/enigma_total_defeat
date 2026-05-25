"""Benchmark every registered technique against generated scenarios.

Measures three things per technique:
  1. Correctness: does it find the right answer given its prerequisites?
  2. Compatibility: which scenario conditions make it useful vs. wasteful?
  3. Timing: how fast is it, and does cost scale with message length?

The benchmark output is a structured compatibility matrix showing which
techniques work under which conditions (plug weight, message length,
known vs. unknown rotors, etc.). This matrix drives the design of an
idealized zero-knowledge attack.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from enigma.language import LanguageModel
from enigma.registry import REGISTRY, Domain
from enigma.scenarios import (
    Scenario,
    make_scenario,
    wrong_trajectory,
    GERMAN_PLAINTEXTS,
    SIMPLE_PLAINTEXTS,
)
from enigma.simulator import fast_trajectory, Plugboard


@dataclass
class BenchmarkResult:
    technique: str
    domain: str
    scenario: str
    success: bool
    metric: float
    metric_name: str
    elapsed: float
    notes: str = ""
    error: str = ""


@dataclass
class CompatibilityEntry:
    technique: str
    domain: str
    works_no_plug: bool | None = None
    works_light_plug: bool | None = None
    works_heavy_plug: bool | None = None
    works_short_msg: bool | None = None
    works_long_msg: bool | None = None
    works_with_rings: bool | None = None
    needs_known_trajectory: bool = False
    needs_known_rotors: bool = False
    needs_decrypted_text: bool = False
    ciphertext_only: bool = False
    avg_time: float = 0.0
    success_rate: float = 0.0


# ------------------------------------------------------------------
# Scenario factory for benchmark conditions
# ------------------------------------------------------------------

def _make_scenarios() -> dict[str, Scenario]:
    long_text = (
        "AUFKLXABTEILUNGXVONXKURTINOWAXKURTINOWAXNORDWESTLX"
        "SEBEZXSEBEZXUAFFLIEGERSTRASZERIQTUNGXDUBROWKIXDUBROWKIX"
        "OPOTSCHKAXOPOTSCHKAXUMXEINSAQTDREINULLXUHRANGETRETENX"
        "ANGRIFFXINFXRGTX"
    )
    return {
        "no_plug_long": make_scenario(
            "no_plug_long", GERMAN_PLAINTEXTS[0],
            rotor_names=("II", "IV", "V"), reflector_name="B",
            positions=(3, 9, 14),
        ),
        "no_plug_short": make_scenario(
            "no_plug_short", SIMPLE_PLAINTEXTS[0],
            rotor_names=("II", "IV", "V"), reflector_name="B",
            positions=(3, 9, 14),
        ),
        "light_plug": make_scenario(
            "light_plug", GERMAN_PLAINTEXTS[1],
            rotor_names=("I", "III", "V"), reflector_name="B",
            positions=(7, 11, 19),
            plugboard_pairs=["AB", "CD", "EF"],
        ),
        "heavy_plug": make_scenario(
            "heavy_plug", long_text,
            rotor_names=("II", "IV", "V"), reflector_name="B",
            positions=(1, 11, 0), ring_settings=(1, 20, 11),
            plugboard_pairs=["AV", "BS", "CG", "DL", "FU",
                             "HZ", "IN", "KM", "OW", "RX"],
        ),
        "with_rings": make_scenario(
            "with_rings", GERMAN_PLAINTEXTS[3],
            rotor_names=("I", "II", "III"), reflector_name="B",
            positions=(5, 17, 8), ring_settings=(0, 0, 15),
        ),
    }


# ------------------------------------------------------------------
# Individual technique benchmarks
# ------------------------------------------------------------------

def _bench_rotor_id(model: LanguageModel, scenarios: dict[str, Scenario]) -> list[BenchmarkResult]:
    results = []
    for sname, s in scenarios.items():
        # spectral_rotor_id
        t = REGISTRY.get("spectral_rotor_id")
        t0 = time.time()
        try:
            ranking = t(s.cipher, s.reflector_name)
            elapsed = time.time() - t0
            top_names = [r for r, _ in ranking]
            correct = s.rotor_names[2]
            rank = top_names.index(correct) + 1 if correct in top_names else -1
            results.append(BenchmarkResult(
                "spectral_rotor_id", "rotor_id", sname,
                success=rank <= 3, metric=rank, metric_name="rank_of_correct",
                elapsed=elapsed,
                notes=f"correct={correct} ranked {rank}/5",
            ))
        except Exception as e:
            results.append(BenchmarkResult(
                "spectral_rotor_id", "rotor_id", sname,
                success=False, metric=-1, metric_name="rank_of_correct",
                elapsed=time.time() - t0, error=str(e),
            ))

        # circular_rotor_id
        t = REGISTRY.get("circular_rotor_id")
        t0 = time.time()
        try:
            ranking = t(s.ciphertext_str)
            elapsed = time.time() - t0
            top_names = [r.right_rotor for r in ranking]
            correct = s.rotor_names[2]
            rank = top_names.index(correct) + 1 if correct in top_names else -1
            results.append(BenchmarkResult(
                "circular_rotor_id", "rotor_id", sname,
                success=rank <= 3, metric=rank, metric_name="rank_of_correct",
                elapsed=elapsed,
                notes=f"correct={correct} ranked {rank}/5",
            ))
        except Exception as e:
            results.append(BenchmarkResult(
                "circular_rotor_id", "rotor_id", sname,
                success=False, metric=-1, metric_name="rank_of_correct",
                elapsed=time.time() - t0, error=str(e),
            ))

    return results


def _bench_position_search(model: LanguageModel, scenarios: dict[str, Scenario]) -> list[BenchmarkResult]:
    results = []
    t = REGISTRY.get("inline_ic_sweep")
    for sname, s in scenarios.items():
        t0 = time.time()
        try:
            ranking = t(s.cipher, s.rotor_names, s.reflector_name,
                        s.ring_settings, top_k=100)
            elapsed = time.time() - t0
            positions = [pos for _, pos in ranking]
            found = s.positions in positions
            rank = positions.index(s.positions) + 1 if found else -1
            results.append(BenchmarkResult(
                "inline_ic_sweep", "position_search", sname,
                success=found, metric=rank, metric_name="rank_of_correct",
                elapsed=elapsed,
                notes=f"rank {rank}/100" if found else "not in top 100",
            ))
        except Exception as e:
            results.append(BenchmarkResult(
                "inline_ic_sweep", "position_search", sname,
                success=False, metric=-1, metric_name="rank_of_correct",
                elapsed=time.time() - t0, error=str(e),
            ))
    return results


def _bench_trajectory_scoring(model: LanguageModel, scenarios: dict[str, Scenario]) -> list[BenchmarkResult]:
    results = []
    for sname, s in scenarios.items():
        wt = wrong_trajectory(s)

        # superposition_filter
        t = REGISTRY.get("superposition_filter")
        t0 = time.time()
        correct_survives = t(s.cipher, s.trajectory, model)
        wrong_survives = t(s.cipher, wt, model)
        elapsed = time.time() - t0
        discriminates = correct_survives and not wrong_survives
        results.append(BenchmarkResult(
            "superposition_filter", "trajectory_score", sname,
            success=correct_survives,
            metric=1.0 if discriminates else 0.5 if correct_survives else 0.0,
            metric_name="discrimination",
            elapsed=elapsed,
            notes=f"correct={correct_survives} wrong={wrong_survives}",
        ))

        # bidirectional_score
        t = REGISTRY.get("bidirectional_score")
        t0 = time.time()
        res_correct = t(s.cipher, s.rotor_names, s.reflector_name,
                        s.positions, s.ring_settings, model)
        wrong_pos = ((s.positions[0]+13)%26, (s.positions[1]+13)%26, (s.positions[2]+13)%26)
        res_wrong = t(s.cipher, s.rotor_names, s.reflector_name,
                      wrong_pos, s.ring_settings, model)
        elapsed = time.time() - t0
        correct_passes = res_correct is not None
        wrong_rejected = res_wrong is None
        results.append(BenchmarkResult(
            "bidirectional_score", "trajectory_score", sname,
            success=correct_passes,
            metric=1.0 if (correct_passes and wrong_rejected) else 0.5 if correct_passes else 0.0,
            metric_name="discrimination",
            elapsed=elapsed,
            notes=f"correct_passes={correct_passes} wrong_rejected={wrong_rejected}",
        ))

        # validation_discriminator
        t_val = REGISTRY.get("validation_discriminator")
        correct_dec = [ord(c) - 65 for c in s.plaintext]
        n_correct = t_val(correct_dec, model)
        # For identity-plug decrypt
        id_dec = [s.trajectory[ti][s.cipher[ti]] for ti in range(len(s.cipher))]
        n_wrong = t_val(id_dec, model)
        has_plug = len(s.plugboard_pairs) > 0
        results.append(BenchmarkResult(
            "validation_discriminator", "trajectory_score", sname,
            success=n_correct == 0,
            metric=n_correct,
            metric_name="excluded_bigrams_correct",
            elapsed=0.0,
            notes=f"correct={n_correct} identity={n_wrong} has_plug={has_plug}",
        ))

    return results


def _bench_plugboard(model: LanguageModel, scenarios: dict[str, Scenario]) -> list[BenchmarkResult]:
    results = []
    plug_techniques = [
        ("beam_swap", lambda s, m: REGISTRY.get("beam_swap")(
            s.cipher, s.trajectory, m, rounds=8, beam_width=50)),
        ("greedy_swap", lambda s, m: REGISTRY.get("greedy_swap")(
            s.cipher, s.trajectory, m)),
        ("domain_cascade_full", lambda s, m: REGISTRY.get("domain_cascade_full")(
            s.cipher, s.trajectory, m)),
        ("hyperchart", lambda s, m: REGISTRY.get("hyperchart")(
            s.cipher, s.trajectory, m, iterations=50)),
        ("signed_propagation", lambda s, m: REGISTRY.get("signed_propagation")(
            s.cipher, s.trajectory, m)),
    ]

    for tech_name, tech_fn in plug_techniques:
        for sname, s in scenarios.items():
            t0 = time.time()
            try:
                raw = tech_fn(s, model)
                elapsed = time.time() - t0

                if tech_name == "beam_swap":
                    score, plug, dec = raw
                    plaintext = "".join(chr(d + 65) for d in dec)
                    match = plaintext == s.plaintext
                    pairs_found = sum(1 for a in range(26) if plug[a] > a)
                    results.append(BenchmarkResult(
                        tech_name, "plugboard", sname,
                        success=match, metric=pairs_found,
                        metric_name="pairs_recovered",
                        elapsed=elapsed,
                        notes=f"match={match} pairs={pairs_found} expected={len(s.plugboard_pairs)}",
                    ))

                elif tech_name == "greedy_swap":
                    score, plug = raw
                    dec = [plug[s.trajectory[ti][plug[s.cipher[ti]]]] for ti in range(len(s.cipher))]
                    plaintext = "".join(chr(d + 65) for d in dec)
                    match = plaintext == s.plaintext
                    pairs_found = sum(1 for a in range(26) if plug[a] > a)
                    results.append(BenchmarkResult(
                        tech_name, "plugboard", sname,
                        success=match, metric=pairs_found,
                        metric_name="pairs_recovered",
                        elapsed=elapsed,
                    ))

                elif tech_name == "domain_cascade_full":
                    if raw is None:
                        results.append(BenchmarkResult(
                            tech_name, "plugboard", sname,
                            success=False, metric=0,
                            metric_name="pairs_recovered",
                            elapsed=elapsed, notes="returned None",
                        ))
                    else:
                        score, plug_map, dec = raw
                        plaintext = "".join(chr(d + 65) for d in dec)
                        match = plaintext == s.plaintext
                        pairs_found = sum(1 for a in range(26) if plug_map[a] != a) // 2
                        results.append(BenchmarkResult(
                            tech_name, "plugboard", sname,
                            success=match, metric=pairs_found,
                            metric_name="pairs_recovered",
                            elapsed=elapsed,
                        ))

                elif tech_name == "hyperchart":
                    hr = raw
                    pairs_found = len(hr.plugboard_pairs)
                    converged = hr.convergence[-1] > hr.convergence[0] if hr.convergence else False
                    plug = hr.plugboard_map
                    dec = [plug[s.trajectory[ti][plug[s.cipher[ti]]]] for ti in range(len(s.cipher))]
                    plaintext = "".join(chr(d + 65) for d in dec)
                    match = plaintext == s.plaintext
                    results.append(BenchmarkResult(
                        tech_name, "plugboard", sname,
                        success=match, metric=pairs_found,
                        metric_name="pairs_found",
                        elapsed=elapsed,
                        notes=f"converged={converged} match={match}",
                    ))

                elif tech_name == "signed_propagation":
                    prop, consistent = raw
                    n_det = prop.n_determined_plug()
                    pairs = prop.plug_pairs()
                    results.append(BenchmarkResult(
                        tech_name, "plugboard", sname,
                        success=consistent, metric=n_det,
                        metric_name="plug_determined",
                        elapsed=elapsed,
                        notes=f"consistent={consistent} det={n_det}/26 pairs={len(pairs)}",
                    ))

            except Exception as e:
                results.append(BenchmarkResult(
                    tech_name, "plugboard", sname,
                    success=False, metric=0,
                    metric_name="error",
                    elapsed=time.time() - t0,
                    error=str(e)[:100],
                ))

    return results


def _bench_ring(model: LanguageModel, scenarios: dict[str, Scenario]) -> list[BenchmarkResult]:
    results = []
    s = scenarios["with_rings"]

    # turnover_ring_refine
    t = REGISTRY.get("turnover_ring_refine")
    t0 = time.time()
    rings, score = t(s.cipher, s.rotor_names, s.reflector_name, s.positions, model)
    elapsed = time.time() - t0
    results.append(BenchmarkResult(
        "turnover_ring_refine", "ring", "with_rings",
        success=rings[2] == s.ring_settings[2],
        metric=rings[2], metric_name="right_ring_found",
        elapsed=elapsed,
        notes=f"found={rings[2]} expected={s.ring_settings[2]}",
    ))

    # crt_ring_refine
    t = REGISTRY.get("crt_ring_refine")
    t0 = time.time()
    rings, score = t(s.cipher, s.rotor_names, s.reflector_name, s.positions, model)
    elapsed = time.time() - t0
    results.append(BenchmarkResult(
        "crt_ring_refine", "ring", "with_rings",
        success=rings[2] == s.ring_settings[2],
        metric=rings[2], metric_name="right_ring_found",
        elapsed=elapsed,
        notes=f"found={rings[2]} expected={s.ring_settings[2]} (CRT decomposition)",
    ))

    return results


# ------------------------------------------------------------------
# Main benchmark runner
# ------------------------------------------------------------------

def run_benchmark(verbose: bool = True) -> tuple[list[BenchmarkResult], list[CompatibilityEntry]]:
    """Run the full benchmark suite. Returns (results, compatibility_matrix)."""
    model = LanguageModel.german_military()
    scenarios = _make_scenarios()

    if verbose:
        print("Generating scenarios...")
        for name, s in scenarios.items():
            print(f"  {name:20s}  len={len(s.cipher):3d}  plug={len(s.plugboard_pairs):2d}  "
                  f"ring={''.join(chr(r+65) for r in s.ring_settings)}")

    all_results: list[BenchmarkResult] = []

    if verbose:
        print("\nBenchmarking rotor identification...")
    all_results.extend(_bench_rotor_id(model, scenarios))

    if verbose:
        print("Benchmarking position search...")
    all_results.extend(_bench_position_search(model, scenarios))

    if verbose:
        print("Benchmarking trajectory scoring...")
    all_results.extend(_bench_trajectory_scoring(model, scenarios))

    if verbose:
        print("Benchmarking plugboard recovery...")
    all_results.extend(_bench_plugboard(model, scenarios))

    if verbose:
        print("Benchmarking ring recovery...")
    all_results.extend(_bench_ring(model, scenarios))

    # Build compatibility matrix
    compat = _build_compatibility(all_results)

    if verbose:
        _print_results(all_results, compat)

    return all_results, compat


def _build_compatibility(results: list[BenchmarkResult]) -> list[CompatibilityEntry]:
    """Derive compatibility matrix from benchmark results."""
    by_tech: dict[str, list[BenchmarkResult]] = {}
    for r in results:
        by_tech.setdefault(r.technique, []).append(r)

    compat: list[CompatibilityEntry] = []
    for tech_name, tech_results in by_tech.items():
        entry = CompatibilityEntry(
            technique=tech_name,
            domain=tech_results[0].domain,
        )

        scenario_success = {}
        scenario_time = {}
        for r in tech_results:
            scenario_success[r.scenario] = r.success
            scenario_time[r.scenario] = r.elapsed

        entry.works_no_plug = scenario_success.get("no_plug_long")
        entry.works_light_plug = scenario_success.get("light_plug")
        entry.works_heavy_plug = scenario_success.get("heavy_plug")
        entry.works_short_msg = scenario_success.get("no_plug_short")
        entry.works_long_msg = scenario_success.get("no_plug_long")
        entry.works_with_rings = scenario_success.get("with_rings")

        times = [r.elapsed for r in tech_results if r.elapsed > 0]
        entry.avg_time = sum(times) / len(times) if times else 0.0

        successes = [r.success for r in tech_results]
        entry.success_rate = sum(successes) / len(successes) if successes else 0.0

        # Dependency classification
        if tech_name in ("spectral_rotor_id", "circular_rotor_id"):
            entry.ciphertext_only = True
        elif entry.domain == "plugboard":
            entry.needs_known_trajectory = True
        elif entry.domain == "ring":
            entry.needs_known_rotors = True
        elif entry.domain == "trajectory_score" and tech_name == "validation_discriminator":
            entry.needs_decrypted_text = True

        compat.append(entry)

    return compat


def _print_results(results: list[BenchmarkResult], compat: list[CompatibilityEntry]):
    """Print formatted benchmark results."""
    print("\n" + "=" * 90)
    print("  BENCHMARK RESULTS")
    print("=" * 90)

    # Group by domain
    domains = {}
    for r in results:
        domains.setdefault(r.domain, []).append(r)

    for domain, domain_results in domains.items():
        print(f"\n--- {domain.upper()} ---")
        for r in domain_results:
            status = "PASS" if r.success else "FAIL"
            print(f"  [{status}] {r.technique:25s} on {r.scenario:16s} "
                  f"{r.metric_name}={r.metric:<6} {r.elapsed:.3f}s  {r.notes}")

    # Compatibility matrix
    print("\n" + "=" * 90)
    print("  COMPATIBILITY MATRIX")
    print("=" * 90)
    print(f"\n  {'Technique':25s} {'Domain':16s} {'NoPl':>5} {'LtPl':>5} "
          f"{'HvPl':>5} {'Short':>5} {'Long':>5} {'Ring':>5} {'Rate':>6} {'Time':>7}")
    print("  " + "-" * 88)

    def _yn(v):
        if v is None:
            return "  -  "
        return "  Y  " if v else "  n  "

    for c in sorted(compat, key=lambda x: (x.domain, x.technique)):
        print(f"  {c.technique:25s} {c.domain:16s} "
              f"{_yn(c.works_no_plug)}{_yn(c.works_light_plug)}"
              f"{_yn(c.works_heavy_plug)}{_yn(c.works_short_msg)}"
              f"{_yn(c.works_long_msg)}{_yn(c.works_with_rings)}"
              f"{c.success_rate:5.0%}  {c.avg_time:6.3f}s")

    # Wasteful combinations
    print("\n" + "=" * 90)
    print("  WASTEFUL COMBINATIONS (technique fails under these conditions)")
    print("=" * 90)
    for c in compat:
        issues = []
        if c.works_heavy_plug is False:
            issues.append("heavy plugboard")
        if c.works_short_msg is False:
            issues.append("short messages")
        if c.works_with_rings is False:
            issues.append("non-trivial rings")
        if c.works_no_plug is False:
            issues.append("no plugboard (!)")
        if issues:
            print(f"  {c.technique:25s}: fails on {', '.join(issues)}")

    # Best per domain
    print("\n" + "=" * 90)
    print("  BEST TECHNIQUE PER DOMAIN (by success rate, then speed)")
    print("=" * 90)
    by_domain: dict[str, list[CompatibilityEntry]] = {}
    for c in compat:
        by_domain.setdefault(c.domain, []).append(c)
    for domain, entries in sorted(by_domain.items()):
        best = sorted(entries, key=lambda x: (-x.success_rate, x.avg_time))
        top = best[0]
        print(f"  {domain:20s}: {top.technique:25s} rate={top.success_rate:.0%} avg={top.avg_time:.3f}s")


if __name__ == "__main__":
    run_benchmark(verbose=True)
