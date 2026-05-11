# core/fingerprint_db.py
"""
Fingerprint Database — the feedback learning loop.

Stores structural signatures of confirmed vulnerabilities so the system
gets smarter with every audit. When a known pattern is detected in a new
target, the engine produces instant hypotheses without waiting for the
full rule engine pass.

This is what makes SecureGraph autonomous rather than a smart scanner:
every confirmed exploit teaches the system a new pattern that it can
recognize instantly on the next target.

Backed by SQLite for portability and zero-config persistence.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from core.graph import StateGraph, NodeType, EdgeType
from core.executor import VerificationResult


@dataclass
class InstantHit:
    """A vulnerability pattern match found instantly via fingerprint matching."""
    vuln_class: str
    endpoint_id: str
    confidence: float
    fingerprint_id: str
    matched_pattern: str
    description: str


# ─── Fingerprint Database ────────────────────────────────────────────────────

class FingerprintDB:
    """
    Persistent store of vulnerability fingerprints.

    Schema:
      fingerprints:
        - id (TEXT PK)
        - vuln_class (TEXT)
        - graph_signature (JSON)  -- the structural pattern that indicates this vuln
        - exploit_template (TEXT)  -- curl command or request sequence
        - confidence (REAL)
        - created_at (REAL)
        - hit_count (INTEGER)      -- how many times this pattern has matched
        - last_hit_at (REAL)
    """

    def __init__(self, db_path: str = "fingerprints.db"):
        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS fingerprints (
                id TEXT PRIMARY KEY,
                vuln_class TEXT NOT NULL,
                graph_signature TEXT NOT NULL,
                exploit_template TEXT,
                confidence REAL DEFAULT 1.0,
                created_at REAL,
                hit_count INTEGER DEFAULT 0,
                last_hit_at REAL
            )
        """)
        self._conn.commit()

    # ── Store ────────────────────────────────────────────────────────────────

    def store_fingerprint(
        self,
        result: VerificationResult,
        graph_signature: dict,
        exploit_template: str = "",
    ) -> str:
        """
        Store a confirmed finding's structural signature.

        Args:
            result: The verified VerificationResult
            graph_signature: Dict describing the graph pattern, e.g.:
                {
                    "vuln_class": "IDOR",
                    "chain_node_types": ["Parameter", "Endpoint"],
                    "chain_edge_types": ["parameter_flows_to"],
                    "endpoint_method": "GET",
                    "auth_required": True,
                    "has_ownership_constraint": False,
                    "param_location": "path",
                    "param_name_pattern": "id",
                }
            exploit_template: Optional curl/request template
        """
        fp_id = f"fp_{result.vuln_class}_{int(time.time())}_{hash(json.dumps(graph_signature, sort_keys=True)) % 10000}"
        cursor = self._conn.cursor()
        cursor.execute(
            """INSERT OR REPLACE INTO fingerprints 
               (id, vuln_class, graph_signature, exploit_template, confidence, created_at, hit_count, last_hit_at)
               VALUES (?, ?, ?, ?, ?, ?, 1, ?)""",
            (
                fp_id,
                result.vuln_class,
                json.dumps(graph_signature),
                exploit_template or json.dumps(result.request_log[:2]),
                result.impact.value == "verified" and 1.0 or 0.85,
                time.time(),
                time.time(),
            ),
        )
        self._conn.commit()
        print(f"  [fingerprint] Stored pattern '{result.vuln_class}' (id={fp_id})")
        return fp_id

    # ── Match ────────────────────────────────────────────────────────────────

    def match_fingerprints(self, graph: StateGraph) -> list[dict]:
        """
        Walk all stored fingerprints and check if any structural pattern
        matches the current graph. Returns instant-hit hypotheses.
        """
        hits = []
        cursor = self._conn.cursor()
        cursor.execute("SELECT id, vuln_class, graph_signature, confidence FROM fingerprints ORDER BY confidence DESC")
        for fp_id, vuln_class, sig_json, confidence in cursor.fetchall():
            try:
                signature = json.loads(sig_json)
            except json.JSONDecodeError:
                continue

            # Match against graph using the signature
            matched_endpoints = self._match_signature(graph, signature)
            for ep_id in matched_endpoints:
                hits.append({
                    "fingerprint_id": fp_id,
                    "vuln_class": vuln_class,
                    "endpoint_id": ep_id,
                    "confidence": confidence,
                    "matched_pattern": signature.get("description", vuln_class),
                })

            # Update hit count if matches found
            if matched_endpoints:
                cursor.execute(
                    "UPDATE fingerprints SET hit_count = hit_count + 1, last_hit_at = ? WHERE id = ?",
                    (time.time(), fp_id),
                )

        self._conn.commit()
        return hits

    def _match_signature(self, graph: StateGraph, signature: dict) -> list[str]:
        """
        Given a graph and a fingerprint signature, find all endpoints that match.

        This is the core pattern-matching engine that makes instant detection work.
        """
        matched = []
        vuln_class = signature.get("vuln_class", "")
        chain_node_types = signature.get("chain_node_types", [])
        chain_edge_types = signature.get("chain_edge_types", [])
        endpoint_method = signature.get("endpoint_method", "")
        auth_required = signature.get("auth_required")
        has_ownership_constraint = signature.get("has_ownership_constraint")
        param_location = signature.get("param_location", "")
        param_name_pattern = signature.get("param_name_pattern", "")

        from core.graph import EndpointNode, ParameterNode

        for ep in graph.endpoints():
            if not isinstance(ep, EndpointNode):
                continue

            # Method filter
            if endpoint_method and ep.method.value != endpoint_method:
                continue

            # Auth filter
            if auth_required is not None and ep.auth_required != auth_required:
                continue

            # Ownership constraint filter
            if has_ownership_constraint is not None:
                ac_owns = any(ac.has_ownership_check() for ac in ep.auth_contexts)
                if ac_owns != has_ownership_constraint:
                    continue

            # Parameter location/name filter (for IDOR-type matches)
            if param_location or param_name_pattern:
                has_matching_param = False
                for edge in graph.incoming(ep.id):
                    if edge.type != EdgeType.PARAM_FLOWS_TO:
                        continue
                    param = graph.get_node(edge.src)
                    if isinstance(param, ParameterNode):
                        loc_match = not param_location or param.location.value == param_location
                        name_match = not param_name_pattern or param_name_pattern.lower() in param.label.lower()
                        if loc_match and name_match:
                            has_matching_param = True
                            break
                if not has_matching_param:
                    continue

            matched.append(ep.id)

        return matched

    # ── Stats ────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Return statistics about the fingerprint database."""
        cursor = self._conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM fingerprints")
        total = cursor.fetchone()[0]
        cursor.execute("SELECT SUM(hit_count) FROM fingerprints")
        total_hits = cursor.fetchone()[0] or 0
        cursor.execute("SELECT vuln_class, COUNT(*) FROM fingerprints GROUP BY vuln_class ORDER BY COUNT(*) DESC")
        by_class = {row[0]: row[1] for row in cursor.fetchall()}
        return {
            "total_fingerprints": total,
            "total_hits": total_hits,
            "by_vuln_class": by_class,
        }

    def get_top_patterns(self, limit: int = 10) -> list[dict]:
        """Return most frequently matched patterns."""
        cursor = self._conn.cursor()
        cursor.execute(
            "SELECT vuln_class, graph_signature, hit_count FROM fingerprints ORDER BY hit_count DESC LIMIT ?",
            (limit,),
        )
        return [
            {"vuln_class": row[0], "signature": json.loads(row[1]), "hits": row[2]}
            for row in cursor.fetchall()
        ]

    # ── Persistence ──────────────────────────────────────────────────────────

    def save(self, path: Optional[str] = None):
        """Backup the database to a file."""
        self._conn.commit()
        if path:
            import shutil
            shutil.copy(self.db_path, path)

    def load(self, path: str):
        """Load fingerprints from a backup."""
        import shutil
        shutil.copy(path, self.db_path)
        self._init_db()

    def close(self):
        if self._conn:
            self._conn.close()