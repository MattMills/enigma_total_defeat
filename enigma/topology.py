"""Rotor topology and operative-structure-space cache.

Each broken message reveals a full operative geometry trajectory —
the sequence of permutations E_0, E_1, ..., E_{L-1}. This trajectory
is uniquely determined by the machine configuration (rotors, positions,
rings, reflector) and is INDEPENDENT of the plugboard and plaintext.

By caching trajectory fingerprints from broken messages, we can test
new ciphertexts against known configurations much faster: instead of
recomputing 26^3 trajectories per rotor triple, we check if the new
ciphertext's trajectory matches any cached fingerprint.

The cache grows monotonically — every broken message adds information
about the operative structure space.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field, asdict
from typing import Any

from enigma.language import LanguageModel, index_of_coincidence
from enigma.simulator import (
    Enigma,
    Plugboard,
    REFLECTORS,
    ROTORS,
    fast_trajectory,
)


# ------------------------------------------------------------------
# Trajectory fingerprint
# ------------------------------------------------------------------


def trajectory_fingerprint(trajectory: list[list[int]], length: int = 8) -> str:
    """Compact hash of a trajectory's first `length` permutations.

    Two trajectories that share the same fingerprint are identical
    for the first `length` positions. This is used as a fast lookup
    key in the topology cache.
    """
    data = []
    for t in range(min(length, len(trajectory))):
        data.extend(trajectory[t])
    h = hashlib.sha256(bytes(data))
    return h.hexdigest()[:16]


def trajectory_signature(trajectory: list[list[int]]) -> list[dict]:
    """Rich signature of a trajectory for JSON serialization.

    Records the cycle structure, fixed-point-free property, and
    inter-position differential at each step.
    """
    sig: list[dict] = []
    for t, E in enumerate(trajectory):
        cycles = _cycle_decomposition(E)
        entry: dict[str, Any] = {
            "t": t,
            "cycle_type": sorted([len(c) for c in cycles], reverse=True),
            "fp_free": all(E[i] != i for i in range(26)),
            "involution": all(E[E[i]] == i for i in range(26)),
        }
        if t > 0:
            # Differential: how many letter mappings changed from t-1 to t.
            prev = trajectory[t - 1]
            diff = sum(1 for i in range(26) if E[i] != prev[i])
            entry["diff_from_prev"] = diff
        sig.append(entry)
    return sig


def _cycle_decomposition(perm: list[int]) -> list[list[int]]:
    seen = [False] * len(perm)
    cycles: list[list[int]] = []
    for i in range(len(perm)):
        if seen[i]:
            continue
        cycle = []
        j = i
        while not seen[j]:
            seen[j] = True
            cycle.append(j)
            j = perm[j]
        cycles.append(cycle)
    return cycles


# ------------------------------------------------------------------
# Topology cache: builds across messages
# ------------------------------------------------------------------


@dataclass
class CachedTrajectory:
    """A single trajectory entry in the cache."""
    fingerprint: str
    rotor_names: tuple[str, str, str]
    reflector_name: str
    positions: tuple[int, int, int]
    ring_settings: tuple[int, int, int]
    fourth_rotor_name: str | None = None
    fourth_position: int = 0
    fourth_ring: int = 0
    message_ids: list[str] = field(default_factory=list)
    trajectory_length: int = 0

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "rotors": list(self.rotor_names),
            "reflector": self.reflector_name,
            "positions": [chr(p + 65) for p in self.positions],
            "rings": [chr(r + 65) for r in self.ring_settings],
            "fourth_rotor": self.fourth_rotor_name,
            "fourth_position": chr(self.fourth_position + 65) if self.fourth_rotor_name else None,
            "message_ids": self.message_ids,
            "trajectory_length": self.trajectory_length,
        }


@dataclass
class TopologyCache:
    """Operative-structure-space cache that grows with each broken message.

    Maps trajectory fingerprints to machine configurations. When
    attacking a new message, we can first check if its trajectory
    matches any cached fingerprint — O(1) lookup instead of O(26^3)
    search.
    """
    entries: dict[str, CachedTrajectory] = field(default_factory=dict)
    # Per-rotor-triple differential signature cache.
    differential_cache: dict[str, list[int]] = field(default_factory=dict)

    def add_trajectory(
        self,
        rotor_names: tuple[str, str, str],
        reflector_name: str,
        positions: tuple[int, int, int],
        ring_settings: tuple[int, int, int],
        length: int,
        message_id: str = "",
        fourth_rotor_name: str | None = None,
        fourth_position: int = 0,
        fourth_ring: int = 0,
    ) -> str:
        """Compute and cache a trajectory. Returns its fingerprint."""
        traj = fast_trajectory(
            rotor_names=rotor_names,
            reflector_name=reflector_name,
            start_positions=positions,
            ring_settings=ring_settings,
            length=length,
            fourth_rotor_name=fourth_rotor_name,
            fourth_position=fourth_position,
            fourth_ring=fourth_ring,
        )
        fp = trajectory_fingerprint(traj)
        if fp in self.entries:
            if message_id and message_id not in self.entries[fp].message_ids:
                self.entries[fp].message_ids.append(message_id)
        else:
            self.entries[fp] = CachedTrajectory(
                fingerprint=fp,
                rotor_names=rotor_names,
                reflector_name=reflector_name,
                positions=positions,
                ring_settings=ring_settings,
                fourth_rotor_name=fourth_rotor_name,
                fourth_position=fourth_position,
                fourth_ring=fourth_ring,
                message_ids=[message_id] if message_id else [],
                trajectory_length=length,
            )
        # Cache the differential signature for this rotor triple.
        triple_key = f"{'-'.join(rotor_names)}/{reflector_name}"
        if triple_key not in self.differential_cache:
            diffs = []
            for t in range(1, len(traj)):
                d = sum(1 for i in range(26) if traj[t][i] != traj[t-1][i])
                diffs.append(d)
            self.differential_cache[triple_key] = diffs
        return fp

    def lookup(self, fingerprint: str) -> CachedTrajectory | None:
        return self.entries.get(fingerprint)

    def match_trajectory(
        self,
        cipher: list[int],
        model: LanguageModel,
        top_k: int = 5,
    ) -> list[tuple[float, CachedTrajectory, list[int]]]:
        """Test a ciphertext against all cached trajectories.

        Returns top-K (score, cache_entry, decrypted) sorted by score.
        """
        results: list[tuple[float, CachedTrajectory, list[int]]] = []
        for entry in self.entries.values():
            traj = fast_trajectory(
                rotor_names=entry.rotor_names,
                reflector_name=entry.reflector_name,
                start_positions=entry.positions,
                ring_settings=entry.ring_settings,
                length=len(cipher),
                fourth_rotor_name=entry.fourth_rotor_name,
                fourth_position=entry.fourth_position,
                fourth_ring=entry.fourth_ring,
            )
            dec = [traj[t][cipher[t]] for t in range(len(cipher))]
            score = model.score(dec)
            if score > float("-inf"):
                results.append((score, entry, dec))
        results.sort(key=lambda x: x[0], reverse=True)
        return results[:top_k]

    def to_json(self, indent: int = 2) -> str:
        """Serialize the full cache to JSON."""
        data = {
            "cache_size": len(self.entries),
            "rotor_triples_seen": list(self.differential_cache.keys()),
            "entries": [e.to_dict() for e in self.entries.values()],
        }
        return json.dumps(data, indent=indent)

    @classmethod
    def from_json(cls, text: str) -> "TopologyCache":
        data = json.loads(text)
        cache = cls()
        for entry_data in data.get("entries", []):
            fp = entry_data["fingerprint"]
            cache.entries[fp] = CachedTrajectory(
                fingerprint=fp,
                rotor_names=tuple(entry_data["rotors"]),
                reflector_name=entry_data["reflector"],
                positions=tuple(ord(c) - 65 for c in entry_data["positions"]),
                ring_settings=tuple(ord(c) - 65 for c in entry_data["rings"]),
                fourth_rotor_name=entry_data.get("fourth_rotor"),
                fourth_position=(
                    ord(entry_data["fourth_position"]) - 65
                    if entry_data.get("fourth_position") else 0
                ),
                message_ids=entry_data.get("message_ids", []),
                trajectory_length=entry_data.get("trajectory_length", 0),
            )
        return cache


# ------------------------------------------------------------------
# Build cache from known messages
# ------------------------------------------------------------------


def build_cache_from_messages() -> TopologyCache:
    """Build the topology cache from all messages with known settings."""
    from enigma.messages import MESSAGES

    cache = TopologyCache()
    for msg in MESSAGES:
        if not msg.rotors or not msg.initial_positions or not msg.reflector:
            continue
        ct_len = len("".join(c for c in msg.ciphertext if "A" <= c <= "Z"))
        if ct_len < 5:
            continue
        positions = tuple(ord(c) - 65 for c in msg.initial_positions)
        rings = tuple(ord(c) - 65 for c in msg.ring_settings)
        fourth = msg.fourth_rotor or None
        fourth_pos = ord(msg.fourth_position) - 65 if msg.fourth_position else 0

        cache.add_trajectory(
            rotor_names=tuple(msg.rotors),
            reflector_name=msg.reflector,
            positions=positions,
            ring_settings=rings,
            length=ct_len,
            message_id=msg.id,
            fourth_rotor_name=fourth,
            fourth_position=fourth_pos,
        )
    return cache


def topology_report(cache: TopologyCache) -> dict:
    """Generate a topology report with visualization-friendly data."""
    from enigma.messages import MESSAGES, get_messages_with_known_solution

    report: dict[str, Any] = {
        "summary": {
            "total_cached_trajectories": len(cache.entries),
            "unique_rotor_triples": len(cache.differential_cache),
            "messages_indexed": sum(
                len(e.message_ids) for e in cache.entries.values()
            ),
        },
        "rotor_topology": {},
        "messages": [],
    }

    # Per-rotor-triple topology.
    for triple_key, diffs in cache.differential_cache.items():
        entries_for_triple = [
            e for e in cache.entries.values()
            if f"{'-'.join(e.rotor_names)}/{e.reflector_name}" == triple_key
        ]
        report["rotor_topology"][triple_key] = {
            "differential_pattern": diffs[:50],
            "avg_diff": sum(diffs) / len(diffs) if diffs else 0,
            "min_diff": min(diffs) if diffs else 0,
            "max_diff": max(diffs) if diffs else 0,
            "turnovers_detected": [
                i for i, d in enumerate(diffs) if d > 20
            ],
            "cached_positions": [
                {"pos": "".join(chr(p+65) for p in e.positions),
                 "rings": "".join(chr(r+65) for r in e.ring_settings),
                 "messages": e.message_ids}
                for e in entries_for_triple
            ],
        }

    # Per-message data.
    for msg in MESSAGES:
        ct_clean = "".join(c for c in msg.ciphertext if "A" <= c <= "Z")
        if len(ct_clean) < 5:
            continue
        msg_data: dict[str, Any] = {
            "id": msg.id,
            "length": len(ct_clean),
            "machine_type": msg.machine_type.value,
            "has_known_key": bool(msg.rotors),
            "has_known_plaintext": bool(msg.known_plaintext),
            "source": msg.source,
        }
        if msg.rotors:
            msg_data["key"] = {
                "rotors": list(msg.rotors),
                "reflector": msg.reflector,
                "positions": msg.initial_positions,
                "rings": msg.ring_settings,
                "plugboard": msg.plugboard,
            }
            if msg.fourth_rotor:
                msg_data["key"]["fourth_rotor"] = msg.fourth_rotor
                msg_data["key"]["fourth_position"] = msg.fourth_position
        if msg.known_plaintext:
            msg_data["plaintext_preview"] = msg.known_plaintext[:80]
        report["messages"].append(msg_data)

    return report
