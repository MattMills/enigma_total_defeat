"""Technique registry: every cryptanalytic attack as a named, testable unit.

Each technique is registered with:
  - A unique name
  - Its domain (what subproblem it solves)
  - Input/output contracts
  - The callable that runs it
  - Metadata (description, limitations)

Domains partition the Enigma key space into subproblems:
  rotor_id        — identify which rotor is in a given slot
  position_search — rank/filter 17,576 starting positions
  trajectory_score — score or filter a (rotor, position) hypothesis
  plugboard       — recover the plugboard given a correct trajectory
  ring            — recover ring settings
  full_solve      — zero-knowledge end-to-end attack
  caching         — trajectory fingerprint caching
  multi_message   — cross-message coupling
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


class Domain(Enum):
    ROTOR_ID = "rotor_id"
    POSITION_SEARCH = "position_search"
    TRAJECTORY_SCORE = "trajectory_score"
    PLUGBOARD = "plugboard"
    RING = "ring"
    FULL_SOLVE = "full_solve"
    CACHING = "caching"
    MULTI_MESSAGE = "multi_message"


@dataclass
class Technique:
    name: str
    domain: Domain
    fn: Callable[..., Any]
    description: str = ""
    limitations: str = ""
    slow: bool = False

    def __call__(self, *args, **kwargs) -> Any:
        return self.fn(*args, **kwargs)


class TechniqueRegistry:
    """Central registry of all cryptanalytic techniques."""

    def __init__(self):
        self._techniques: dict[str, Technique] = {}

    def register(
        self,
        name: str,
        domain: Domain,
        fn: Callable[..., Any],
        description: str = "",
        limitations: str = "",
        slow: bool = False,
    ) -> Technique:
        t = Technique(name=name, domain=domain, fn=fn,
                      description=description, limitations=limitations, slow=slow)
        self._techniques[name] = t
        return t

    def get(self, name: str) -> Technique:
        return self._techniques[name]

    def list_all(self) -> list[Technique]:
        return list(self._techniques.values())

    def list_by_domain(self, domain: Domain) -> list[Technique]:
        return [t for t in self._techniques.values() if t.domain == domain]

    def names(self) -> list[str]:
        return list(self._techniques.keys())

    def __len__(self) -> int:
        return len(self._techniques)

    def __contains__(self, name: str) -> bool:
        return name in self._techniques


# ------------------------------------------------------------------
# Global registry instance with all techniques
# ------------------------------------------------------------------

def build_registry() -> TechniqueRegistry:
    """Build the global registry with all implemented techniques."""
    reg = TechniqueRegistry()

    # === ROTOR IDENTIFICATION ===

    from enigma.spectral import identify_right_rotor, compute_rotor_signature

    def spectral_identify(cipher, reflector_name="B", candidate_rotors=("I", "II", "III", "IV", "V")):
        return identify_right_rotor(cipher, reflector_name, tuple(candidate_rotors))

    reg.register(
        "spectral_rotor_id",
        Domain.ROTOR_ID,
        spectral_identify,
        description="Identify right rotor from ciphertext differential profile via Pearson correlation",
        limitations="Weak on messages shorter than 200 characters",
    )

    def spectral_signature(rotor_name, reflector_name="B"):
        return compute_rotor_signature(rotor_name, reflector_name)

    reg.register(
        "spectral_signature",
        Domain.ROTOR_ID,
        spectral_signature,
        description="Compute irreducible spectral signature of a rotor wiring",
    )

    from enigma.circular import circular_attack

    def circular_rotor_id(cipher_str, candidate_right_rotors=("I", "II", "III", "IV", "V"), reflector="B"):
        return circular_attack(cipher_str, candidate_right_rotors=candidate_right_rotors, reflector=reflector)

    reg.register(
        "circular_rotor_id",
        Domain.ROTOR_ID,
        circular_rotor_id,
        description="Circular projection attack: project rotors into R^676, cross-correlate with ciphertext",
    )

    # === POSITION SEARCH ===

    from enigma.language import index_of_coincidence
    from enigma.simulator import fast_trajectory

    def ic_filter(cipher, rotor_names, reflector_name, ring_settings, top_k=500, **fourth_kw):
        from enigma.pipeline import stage_ic_filter
        return stage_ic_filter(cipher, rotor_names, reflector_name, ring_settings, top_k, **fourth_kw)

    reg.register(
        "ic_filter",
        Domain.POSITION_SEARCH,
        ic_filter,
        description="Rank all 17,576 positions by IC (plugboard-invariant)",
        limitations="Slow (~30s for full sweep); correct position typically in top 3%",
        slow=True,
    )

    from enigma.pipeline import _inline_ic_sweep

    reg.register(
        "inline_ic_sweep",
        Domain.POSITION_SEARCH,
        _inline_ic_sweep,
        description="Fast inlined IC sweep (~10x faster than stage_ic_filter)",
    )

    # === TRAJECTORY SCORING / FILTERING ===

    from enigma.superposition import try_collapse

    def superposition_check(cipher, trajectory, model, seed_letters=(4, 13, 8, 18, 17, 0, 19)):
        for seed in seed_letters:
            if seed == cipher[0]:
                continue
            result = try_collapse(cipher, trajectory, model, seed, 0)
            if result.consistent:
                return True
        return False

    reg.register(
        "superposition_filter",
        Domain.TRAJECTORY_SCORE,
        superposition_check,
        description="Reject inconsistent trajectories via constructive constraint propagation (~59% rejection)",
    )

    from enigma.superposition import try_collapse as _try_collapse

    reg.register(
        "superposition_collapse",
        Domain.TRAJECTORY_SCORE,
        _try_collapse,
        description="Full superposition collapse: seed a plaintext letter and propagate constructively",
    )

    from enigma.circular import bidirectional_score

    reg.register(
        "bidirectional_score",
        Domain.TRAJECTORY_SCORE,
        bidirectional_score,
        description="Forward+backward bigram rejection; doubles constraint power at negligible cost",
    )

    from enigma.pipeline import stage_validate

    def validation_discriminator(decrypted, model):
        return stage_validate(decrypted, model)

    reg.register(
        "validation_discriminator",
        Domain.TRAJECTORY_SCORE,
        validation_discriminator,
        description="Binary discriminator: count excluded bigrams (0 = correct, >0 = wrong)",
    )

    from enigma.pipeline import count_valid_ngrams

    reg.register(
        "ngram_counter",
        Domain.TRAJECTORY_SCORE,
        count_valid_ngrams,
        description="Count valid bigrams, trigrams (bigram-of-bigrams), and quadgrams",
    )

    # === PLUGBOARD RECOVERY ===

    from enigma.attack import beam_swap_search

    reg.register(
        "beam_swap",
        Domain.PLUGBOARD,
        beam_swap_search,
        description="N-gram beam search over swap/unpair operations; primary plugboard recovery method",
    )

    from enigma.attack import infer_plugboard

    def greedy_swap_from_trajectory(cipher, trajectory, model, max_pairs=10, min_gain=0.05):
        L = len(cipher)
        dec = [trajectory[t][cipher[t]] for t in range(L)]
        pairs, improved = infer_plugboard(dec, model, max_pairs, min_gain)
        plug = list(range(26))
        for a, b in pairs:
            plug[a] = b
            plug[b] = a
        return model.score(improved), plug

    reg.register(
        "greedy_swap",
        Domain.PLUGBOARD,
        greedy_swap_from_trajectory,
        description="Simple greedy swap: try all (a,b) pairs, swap if gain > threshold",
    )

    from enigma.crack import crack_trajectory

    reg.register(
        "domain_cascade",
        Domain.PLUGBOARD,
        crack_trajectory,
        description="Domain-based cascade with back-propagation; narrows plugboard domains per letter",
    )

    from enigma.crack import crack_message

    reg.register(
        "domain_cascade_full",
        Domain.PLUGBOARD,
        crack_message,
        description="Full domain cascade: crack_trajectory + best-guess plugboard + full decryption",
    )

    from enigma.hyperchart import solve_hyperchart

    reg.register(
        "hyperchart",
        Domain.PLUGBOARD,
        solve_hyperchart,
        description="Birkhoff polytope annealing: projective multi-peak resolution with temperature cooling",
        limitations="Convergence issues on heavy plugboards (>8 pairs)",
    )

    from enigma.unwind import unwind_attack, unwind_bidirectional

    reg.register(
        "unwind_bidirectional",
        Domain.PLUGBOARD,
        unwind_bidirectional,
        description="Bidirectional beam search building plugboard entries from both ends",
        limitations="Beam scoring can prune correct path on heavy plugboards",
    )

    reg.register(
        "unwind_attack",
        Domain.PLUGBOARD,
        unwind_attack,
        description="Full unwind attack: bidirectional unwind + plugboard map + full decryption",
    )

    from enigma.propagate import SignedPropagator

    def signed_propagation(cipher, trajectory, model):
        prop = SignedPropagator(cipher, trajectory, model)
        consistent = prop.propagate()
        return prop, consistent

    reg.register(
        "signed_propagation",
        Domain.PLUGBOARD,
        signed_propagation,
        description="Simultaneous constraint propagation on plaintext + plugboard signed sets",
    )

    from enigma.propagate import branch_and_prune

    reg.register(
        "branch_and_prune",
        Domain.PLUGBOARD,
        branch_and_prune,
        description="Branch only at free positions; prune via beam + dedup; ~5 branching positions needed",
        slow=True,
    )

    from enigma.solver import PlugboardSolver

    def arc_consistency_plugboard(decrypted, candidates):
        solver = PlugboardSolver.from_decryption(decrypted, candidates)
        return solver

    reg.register(
        "arc_consistency",
        Domain.PLUGBOARD,
        arc_consistency_plugboard,
        description="Arc-consistency constraint propagation on exclusory graph (P(a)=b => P(b)=a)",
    )

    from enigma.superposition import collapse_attack

    reg.register(
        "collapse_attack",
        Domain.PLUGBOARD,
        collapse_attack,
        description="Full superposition collapse attack: sweep 17,576 positions × seed letters",
        slow=True,
    )

    # === RING RECOVERY ===

    from enigma.pipeline import _crt_ring_refine

    reg.register(
        "crt_ring_refine",
        Domain.RING,
        _crt_ring_refine,
        description="CRT ring refinement: decompose 26 = 2 × 13, test 15 instead of 26",
    )

    from enigma.solver import refine_ring_from_turnover, detect_turnover_position

    reg.register(
        "turnover_ring_refine",
        Domain.RING,
        refine_ring_from_turnover,
        description="Try all 26 right ring settings, score each with language model",
    )

    reg.register(
        "turnover_detect",
        Domain.RING,
        detect_turnover_position,
        description="Detect rotor turnover position from quality drop in decryption",
    )

    # === FULL SOLVE ===

    from enigma.adelic import run_adelic

    reg.register(
        "adelic",
        Domain.FULL_SOLVE,
        run_adelic,
        description="Gold-coded interference space with manifold beliefs; zero-knowledge solver",
        limitations="Stochastic; may not converge on all messages",
        slow=True,
    )

    from enigma.solver import progressive_solve

    reg.register(
        "progressive_solve",
        Domain.FULL_SOLVE,
        progressive_solve,
        description="Phase A/B/C progressive solver: trajectory → ring → plugboard",
        slow=True,
    )

    from enigma.circular import full_circular_solve

    reg.register(
        "circular_full_solve",
        Domain.FULL_SOLVE,
        full_circular_solve,
        description="Three-stage circular projection: right → middle → left rotor identification",
        slow=True,
    )

    from enigma.circular import bidirectional_attack

    reg.register(
        "bidirectional_attack",
        Domain.FULL_SOLVE,
        bidirectional_attack,
        description="Full brute-force with bidirectional constraint checking",
        slow=True,
    )

    from enigma.hyperchart import hyperchart_attack

    reg.register(
        "hyperchart_attack",
        Domain.FULL_SOLVE,
        hyperchart_attack,
        description="IC pre-filter → projective multi-peak resolution",
        slow=True,
    )

    from enigma.pipeline import crack_full, crack_with_known_trajectory, crack_zero_knowledge

    reg.register(
        "pipeline_full",
        Domain.FULL_SOLVE,
        crack_full,
        description="Integrated 6-stage pipeline: spectral → IC → superposition → domain cascade → beam swap → validation",
        slow=True,
    )

    reg.register(
        "pipeline_known_trajectory",
        Domain.FULL_SOLVE,
        crack_with_known_trajectory,
        description="Pipeline with known trajectory: domain cascade → beam swap → validation",
    )

    reg.register(
        "pipeline_zero_knowledge",
        Domain.FULL_SOLVE,
        crack_zero_knowledge,
        description="Zero-knowledge hierarchical solver: rotor manifold → position → ring → plugboard",
        slow=True,
    )

    # === CACHING ===

    from enigma.topology import TopologyCache, trajectory_fingerprint, build_cache_from_messages

    reg.register(
        "topology_fingerprint",
        Domain.CACHING,
        trajectory_fingerprint,
        description="Compact SHA-256 hash of trajectory's first N permutations",
    )

    def topology_cache_build():
        return build_cache_from_messages()

    reg.register(
        "topology_cache_build",
        Domain.CACHING,
        topology_cache_build,
        description="Build topology cache from all known messages",
    )

    def topology_cache_match(cache, cipher, model, top_k=5):
        return cache.match_trajectory(cipher, model, top_k)

    reg.register(
        "topology_cache_match",
        Domain.CACHING,
        topology_cache_match,
        description="Test ciphertext against all cached trajectories",
    )

    # === MULTI-MESSAGE ===

    from enigma.coupled import coupled_hyperchart, multi_message_attack

    reg.register(
        "coupled_hyperchart",
        Domain.MULTI_MESSAGE,
        coupled_hyperchart,
        description="Simultaneous plugboard resolution from multiple same-day messages",
        limitations="Convergence depends on message length and plugboard weight",
    )

    reg.register(
        "multi_message_attack",
        Domain.MULTI_MESSAGE,
        multi_message_attack,
        description="Full multi-message attack: IC rank per message → coupled hyperchart",
        slow=True,
    )

    return reg


REGISTRY = build_registry()
