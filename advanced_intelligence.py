"""
advanced_intelligence.py — Research-Level Intelligence Layer
=============================================================
Implements 6 advanced AI-driven subsystems that augment the existing defense
modules without replacing them:

  1. UnsupervisedAnomalyDetector  — IsolationForest-based ML anomaly scoring
  2. VectorKnowledgeBase          — FAISS-backed persistent attack memory
  3. PolymorphicPatternGeneralizer — DBSCAN + LCS for zero-day rule synthesis
  4. CrossIPThreatCorrelator      — Cosine-similarity botnet/campaign detection
  5. BayesianDecisionEngine       — Probabilistic fusion of all evidence signals
  6. EvolutionController          — Feedback loop: retrain + inject + optimize

All classes are designed to integrate non-invasively into the existing pipeline.
The only integration points are:
  - BehaviorAnalyzer feature dict  (input)
  - RiskEngine score dict          (augmented)
  - AdaptiveDefense                (action override)
  - SelfHealingEngine / database   (rule injection)
"""

import re
import os
import time
import json
import math
import pickle
import hashlib
import logging
import difflib
import threading
import numpy as np
from typing import Dict, List, Tuple, Optional
from collections import deque, defaultdict

from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import normalize

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Configuration constants
# ──────────────────────────────────────────────────────────────────────────────

FAISS_INDEX_PATH = "vector_memory.faiss"
KB_METADATA_PATH = "vector_memory_meta.json"
EMBEDDING_DIM = 64          # Lightweight behavioral embedding (no heavy model needed)
KB_MAX_ENTRIES = 10_000
EVOLUTION_POOL_MIN = 8      # Trigger generalization after N confirmed hits
RETRAIN_COOLDOWN = 600      # Seconds between evolution-triggered retrains
CORRELATION_WINDOW = 300    # Seconds to keep active IP behavioral vectors
BAYES_PRIOR = 0.04          # P(attack) prior — 4% of production traffic is hostile


# ──────────────────────────────────────────────────────────────────────────────
# 1. UnsupervisedAnomalyDetector
#    Uses IsolationForest on the same 12-dim feature vector as ml_anomaly_detector
#    but adds a live "normal baseline shrinkage" strategy for runtime adaptation.
# ──────────────────────────────────────────────────────────────────────────────

class UnsupervisedAnomalyDetector:
    """
    Standalone IsolationForest running exclusively on the new advanced pipeline.
    Complements (does NOT replace) the existing MLAnomalyDetector in
    ml_anomaly_detector.py. This instance focuses on the *cross-IP* aggregate
    feature vector and provides the raw IF score to BayesianDecisionEngine.
    """

    FEATURE_NAMES = [
        "req_rate_60s", "burst_flag", "failure_rate", "consecutive_fails",
        "unique_endpoints", "sensitive_hits", "scan_flag", "payload_flags",
        "ua_diversity", "acceleration", "new_endpoint_ratio", "session_count",
    ]

    def __init__(self, contamination: float = 0.05):
        self._contamination = contamination
        self._model: Optional[IsolationForest] = None
        self._normal_buf: deque = deque(maxlen=4000)
        self._attack_buf: deque = deque(maxlen=1000) # Labeled attack samples
        self._lock = threading.RLock()
        self._trained = False
        self._bootstrap()

    # ── Public ─────────────────────────────────────────────────────────────

    def score(self, features: dict) -> Tuple[float, bool]:
        """
        Returns (calibrated_anomaly_probability [0,1], is_anomaly bool).
        """
        try:
            vec = self._extract(features)
            with self._lock:
                if not self._trained:
                    return self._heuristic(vec), False
                
                arr = np.array([vec], dtype=np.float64)
                # decision_function: high score -> normal, low score -> anomaly
                raw = self._model.decision_function(arr)[0]
                pred = self._model.predict(arr)[0]
                
                # Calibration: Mapping IF decision score to a [0,1] probability
                prob = self._sigmoid(-raw * 10.0 + 1.2)
                is_anom = pred == -1
                
                # SAFETY: Do NOT automatically add back to normal buffer. 
                # This must be done via feed_label ONLY after verification.
                return round(prob, 4), is_anom
        except Exception as e:
            logger.error(f"[AnomalyDetector] Scoring error: {e}")
            return 0.5, False # Neutral fallback 

    def feed_label(self, features: dict, is_attack: bool, trusted: bool = False):
        """
        Safety-first labeling.
        - Training on attacks: Only if confirmed by honeypot/expert.
        - Training on normal: Only if 'trusted' (legacy reliability or manual white-list).
        """
        if not trusted and not is_attack:
            # Prevents subtle data poisoning from slow, low-intensity 'look normal' attacks
            return

        vec = self._extract(features)
        with self._lock:
            if is_attack:
                self._attack_buf.append(vec)
            else:
                self._normal_buf.append(vec)

    def retrain(self):
        """
        Retrain on the current buffer. 
        Implements concept drift via the sliding window nature of the deques.
        """
        with self._lock:
            if len(self._normal_buf) < 100:
                return
            
            X_norm = list(self._normal_buf)
            X_atk = list(self._attack_buf)
            
            # Combine for training
            X = np.array(X_norm + X_atk, dtype=np.float64)
            
            # Update contamination based on actual observed ratio
            actual_contamination = max(0.01, min(0.3, len(X_atk) / (len(X) + 1e-9)))
            
            self._model = IsolationForest(
                n_estimators=250,
                contamination=actual_contamination,
                random_state=42,
                n_jobs=-1,
                warm_start=False
            )
            self._model.fit(X)
            self._trained = True
            logger.info(f"[AnomalyDetector] Retrained: n={len(X)}, contamination={actual_contamination:.3f}")

    def get_stats(self) -> dict:
        return {
            "trained": self._trained,
            "normal_samples": len(self._normal_buf),
            "attack_samples": len(self._attack_buf),
            "predicted_contamination": self._contamination,
        }

    # ── Private ────────────────────────────────────────────────────────────

    def _bootstrap(self):
        """Generate synthetic normal traffic for cold start."""
        rng = np.random.default_rng(42)
        samples = []
        for _ in range(600):
            samples.append([
                float(rng.poisson(6)),          # req_rate_60s
                0.0,                             # burst_flag
                float(rng.beta(1, 10)),          # failure_rate
                float(rng.integers(0, 2)),       # consecutive_fails
                float(rng.integers(1, 5)),       # unique_endpoints
                0.0,                             # sensitive_hits
                0.0,                             # scan_flag
                0.0,                             # payload_flags
                float(rng.integers(1, 3)),       # ua_diversity
                float(rng.lognormal(0.05, 0.2)), # acceleration
                float(rng.beta(1, 8)),           # new_endpoint_ratio
                float(rng.integers(1, 3)),       # session_count
            ])
        self._normal_buf.extend(samples)
        threading.Thread(target=self.retrain, daemon=True).start()

    @staticmethod
    def _extract(f: dict) -> list:
        freq = f.get("frequency", {})
        fail = f.get("failure", {})
        patt = f.get("pattern", {})
        payl = f.get("payload", {})
        sess = f.get("session", {})
        base = f.get("baseline_deviation", {})
        total = max(freq.get("requests_in_window", 1), 1)
        return [
            min(freq.get("requests_in_window", 0), 200),
            1.0 if freq.get("burst_detected") else 0.0,
            min(fail.get("failure_rate", 0.0), 1.0),
            min(fail.get("consecutive_failures", 0), 20),
            min(patt.get("unique_endpoints", 0), 50),
            min(patt.get("sensitive_hits", 0), 10),
            1.0 if patt.get("scan_pattern") else 0.0,
            min(len(payl.get("current_flags", [])), 5),
            min(sess.get("unique_user_agents", 0), 10),
            min(freq.get("acceleration", 1.0), 20.0),
            len(base.get("new_endpoints", [])) / total,
            min(sess.get("unique_sessions", 0), 10),
        ]

    @staticmethod
    def _sigmoid(x: float) -> float:
        if x >= 0:
            return 1.0 / (1.0 + math.exp(-x))
        z = math.exp(x)
        return z / (1.0 + z)

    @staticmethod
    def _heuristic(vec: list) -> float:
        score = 0.0
        if vec[0] > 50:  score += 0.3
        if vec[1] > 0:   score += 0.2
        if vec[2] > 0.7: score += 0.25
        if vec[6] > 0:   score += 0.2
        if vec[7] > 2:   score += 0.2
        return min(1.0, score)


# ──────────────────────────────────────────────────────────────────────────────
# 2. VectorKnowledgeBase
#    Lightweight FAISS-like search without requiring faiss installation.
#    Uses numpy for inner-product lookups. Auto-falls back safely.
# ──────────────────────────────────────────────────────────────────────────────

class VectorKnowledgeBase:
    """
    Persistent attack memory using vector embeddings.
    Attempts to use faiss-cpu if installed; otherwise falls back to
    a numpy cosine-similarity brute-force search.

    Stores:
      - payload behavior embeddings (64-dim)
      - attack metadata: type, source IPs, first/last seen, mitigation
    """

    def __init__(self, dim: int = EMBEDDING_DIM):
        self._dim = dim
        self._lock = threading.RLock()
        self._vectors: List[np.ndarray] = []
        self._metadata: List[dict] = []
        self._faiss_index = None
        self._use_faiss = self._try_init_faiss()
        self._load()

    # ── Public ─────────────────────────────────────────────────────────────

    def memorize(self, embedding: np.ndarray, meta: dict) -> str:
        """Stores an attack embedding + metadata with temporal importance."""
        emb = self._normalize(embedding)
        with self._lock:
            if len(self._vectors) >= KB_MAX_ENTRIES:
                self._vectors.pop(0)
                self._metadata.pop(0)
            # Store with arrival timestamp for concept drift handling
            self._vectors.append(emb)
            self._metadata.append({
                **meta, 
                "stored_at": time.time(),
                "initial_relevance": 1.0
            })
            if self._use_faiss:
                self._faiss_index.add(emb.reshape(1, -1).astype("float32"))
            entry_id = hashlib.sha256(emb.tobytes()).hexdigest()[:16]
        return entry_id

    def query(self, embedding: np.ndarray, threshold: float = 0.5) -> Tuple[float, dict]:
        """Find the most similar entry in the knowledge base."""
        emb = self._normalize(embedding)
        with self._lock:
            if not self._vectors:
                return 0.0, {}

            if self._use_faiss:
                import faiss
                try:
                    # Search for top-1 nearest neighbor
                    D, I = self._faiss_index.search(emb.reshape(1, -1).astype("float32"), 1)
                    if I[0][0] != -1:
                        idx = int(I[0][0])
                        sim = float(D[0][0])
                        return sim, self._metadata[idx]
                except Exception as e:
                    logger.error(f"[KB] FAISS query error: {e}")
                    # fallback to numpy

            # Numpy cosine similarityfallback
            X = np.array(self._vectors)
            similarities = np.dot(X, emb)
            idx = np.argmax(similarities)
            sim = float(similarities[idx])
            
            return sim, self._metadata[idx]

    def remove(self, embedding: np.ndarray):
        """Remove an entry from the knowledge base (e.g. if confirmed False Positive)."""
        emb = self._normalize(embedding)
        with self._lock:
            if not self._vectors:
                return
            
            # Find the closest entry
            X = np.array(self._vectors)
            similarities = np.dot(X, emb)
            idx = np.argmax(similarities)
            
            if similarities[idx] > 0.99: # Only remove if it's an exact match
                self._vectors.pop(idx)
                self._metadata.pop(idx)
                # If using faiss, we have to rebuild the index (IndexFlatIP doesn't support removal easily)
                if self._use_faiss:
                    self._faiss_index.reset()
                    if self._vectors:
                        arr = np.array(self._vectors, dtype="float32")
                        self._faiss_index.add(arr)
                logger.info(f"[KB] Removed misclassified entry at index {idx}")

    def save(self):
        """Persist index and metadata to disk with safe atomicity."""
        with self._lock:
            if not self._vectors: return
            try:
                temp_meta = KB_METADATA_PATH + ".tmp"
                meta_out = []
                vec_out = []
                for v, m in zip(self._vectors, self._metadata):
                    vec_out.append(v.tolist())
                    meta_out.append(m)
                
                with open(temp_meta, "w") as f:
                    json.dump({"vectors": vec_out, "metadata": meta_out}, f)
                
                if os.path.exists(KB_METADATA_PATH):
                    os.replace(temp_meta, KB_METADATA_PATH)
                else:
                    os.rename(temp_meta, KB_METADATA_PATH)

                if self._use_faiss:
                    import faiss
                    faiss.write_index(self._faiss_index, FAISS_INDEX_PATH)
                logger.info(f"[KB] Safely persisted {len(self._vectors)} entries.")
            except Exception as e:
                logger.error(f"[KB] Save failed: {e}")

    def get_stats(self) -> dict:
        return {
            "entries": len(self._vectors),
            "backend": "faiss" if self._use_faiss else "numpy",
            "dim": self._dim,
        }

    # ── Private ────────────────────────────────────────────────────────────

    def _try_init_faiss(self) -> bool:
        try:
            import faiss
            index = faiss.IndexFlatIP(self._dim)
            self._faiss_index = index
            logger.info("[KB] Using FAISS backend.")
            return True
        except ImportError:
            logger.info("[KB] faiss-cpu not installed. Using numpy fallback.")
            return False

    def _load(self):
        try:
            if not os.path.exists(KB_METADATA_PATH):
                return
            with open(KB_METADATA_PATH) as f:
                data = json.load(f)
            for v, m in zip(data.get("vectors", []), data.get("metadata", [])):
                arr = np.array(v, dtype=np.float64)
                self._vectors.append(arr)
                self._metadata.append(m)
                if self._use_faiss:
                    self._faiss_index.add(arr.reshape(1, -1).astype("float32"))
            logger.info(f"[KB] Loaded {len(self._vectors)} entries from disk.")
        except Exception as e:
            logger.warning(f"[KB] Load failed: {e}")

    @staticmethod
    def _normalize(v: np.ndarray) -> np.ndarray:
        n = np.linalg.norm(v)
        return v / (n + 1e-12)


# ──────────────────────────────────────────────────────────────────────────────
# 3. PolymorphicPatternGeneralizer
#    DBSCAN clustering on payload structural fingerprints,
#    LCS-based invariant extraction, dynamic regex synthesis.
# ──────────────────────────────────────────────────────────────────────────────

class PolymorphicPatternGeneralizer:
    """
    Clusters unknown, suspicious payloads and extracts invariant core strings.
    Converts those cores into generalized regex patterns that can be injected
    into the active defense rule set — including zero-day variants.
    """

    def __init__(self, eps: float = 0.35, min_samples: int = 4):
        self._eps = eps
        self._min_samples = min_samples
        self._lock = threading.RLock()

    def generalize(self, payloads: List[str]) -> List[dict]:
        """
        Clusters unknown, suspicious payloads and extracts invariant core strings.
        Includes safety validation and confidence scoring.
        """
        if len(payloads) < self._min_samples:
            return []

        try:
            fingerprints = [self._fingerprint(p) for p in payloads]
            vecs = self._vectorize(fingerprints)

            labels = DBSCAN(
                eps=self._eps,
                min_samples=self._min_samples,
                metric="cosine",
            ).fit_predict(vecs)

            rules = []
            for cid in set(labels):
                if cid == -1:
                    continue
                cluster_payloads = [payloads[i] for i in range(len(labels)) if labels[i] == cid]
                
                # Rule Logic Improvement: Confidence is derived from cluster size and stability
                confidence = min(1.0, len(cluster_payloads) / 20.0)
                if confidence < 0.3: continue # Ignore low-confidence clusters

                core = self._lcs_cluster(cluster_payloads)
                if len(core) < 7: # Reject overly generic rules (poisoning risk)
                    continue
                
                pattern = self._to_regex(core)
                rules.append({
                    "pattern": pattern,
                    "severity": "HIGH" if confidence > 0.8 else "MEDIUM",
                    "description": f"PolyGen: confidence={confidence:.2f}, n={len(cluster_payloads)}",
                    "confidence": confidence,
                    "ttl": 3600 * 24, # 24h default for auto-gen rules
                    "cluster_size": len(cluster_payloads),
                })
            return rules
        except Exception as e:
            logger.error(f"[Generalizer] Generation failed: {e}")
            return []

    # ── Private ────────────────────────────────────────────────────────────

    @staticmethod
    def _fingerprint(payload: str) -> str:
        """
        Structural fingerprinting: collapse runs of digits→D, letters→A,
        punctuation preserved. Captures structural similarity across mutations.
        """
        s = re.sub(r'[0-9]+', 'D', payload)
        s = re.sub(r'[a-zA-Z]+', 'A', s)
        return s[:512]

    @staticmethod
    def _vectorize(fingerprints: List[str]) -> np.ndarray:
        """
        N-gram character frequency vector (tri-gram TF) over fingerprints.
        Simple but effective for structural similarity.
        """
        vocab: Dict[str, int] = {}
        for fp in fingerprints:
            for i in range(len(fp) - 2):
                ngram = fp[i:i+3]
                if ngram not in vocab:
                    vocab[ngram] = len(vocab)
        dim = max(len(vocab), 1)
        mat = np.zeros((len(fingerprints), dim), dtype=np.float32)
        for r, fp in enumerate(fingerprints):
            for i in range(len(fp) - 2):
                ngram = fp[i:i+3]
                if ngram in vocab:
                    mat[r, vocab[ngram]] += 1
        # L2 normalize rows
        norms = np.linalg.norm(mat, axis=1, keepdims=True) + 1e-12
        return mat / norms

    @staticmethod
    def _lcs_cluster(strings: List[str]) -> str:
        """Extract longest common substring across all strings in cluster."""
        if not strings:
            return ""
        candidate = strings[0]
        for s in strings[1:]:
            m = difflib.SequenceMatcher(None, candidate, s).find_longest_match(
                0, len(candidate), 0, len(s)
            )
            candidate = candidate[m.a: m.a + m.size]
            if len(candidate) < 4:
                return ""
        return candidate

    @staticmethod
    def _to_regex(core: str) -> str:
        """Convert a literal core string into a lenient regex rule."""
        escaped = re.escape(core)
        return f".*{escaped}.*"


# ──────────────────────────────────────────────────────────────────────────────
# 4. CrossIPThreatCorrelator
#    Cosine similarity of behavioral embeddings across active sessions.
#    Detects botnets, distributed scans, and coordinated credential attacks.
# ──────────────────────────────────────────────────────────────────────────────

class CrossIPThreatCorrelator:
    """
    Maintains a sliding window of behavioral embeddings per IP address.
    Computes pairwise cosine similarity to detect coordinated attacks.

    Returns:
      - correlation_score: float [0, 1] — 1.0 = exact behavioral twin
      - campaign_ips:     list of correlated IPs (potential campaign members)
    """

    def __init__(self, window_seconds: int = CORRELATION_WINDOW):
        self._window = window_seconds
        self._sessions: Dict[str, dict] = {}  # ip → {vec, timestamp}
        self._lock = threading.RLock()

    def update(self, ip: str, embedding: np.ndarray):
        """Register / refresh an IP's behavioral embedding."""
        n = np.linalg.norm(embedding)
        norm_vec = embedding / (n + 1e-12)
        with self._lock:
            self._sessions[ip] = {"vec": norm_vec, "ts": time.time()}
            self._evict_stale()

    def correlate(self, target_ip: str) -> Tuple[float, List[str]]:
        """
        Compute max cosine similarity between target_ip and all other IPs.
        Returns (max_similarity, list_of_correlated_ips_above_threshold).
        """
        with self._lock:
            self._evict_stale()
            if target_ip not in self._sessions or len(self._sessions) < 2:
                return 0.0, []

            target_vec = self._sessions[target_ip]["vec"]
            correlated = []
            max_sim = 0.0

            for ip, data in self._sessions.items():
                if ip == target_ip:
                    continue
                sim = float(np.dot(target_vec, data["vec"]))
                if sim > 0.88:
                    correlated.append(ip)
                if sim > max_sim:
                    max_sim = sim

        return round(max_sim, 4), correlated

    def get_active_sessions(self) -> int:
        with self._lock:
            self._evict_stale()
            return len(self._sessions)

    def _evict_stale(self):
        now = time.time()
        stale = [ip for ip, d in self._sessions.items() if now - d["ts"] > self._window]
        for ip in stale:
            del self._sessions[ip]


# ──────────────────────────────────────────────────────────────────────────────
# 5. BayesianDecisionEngine
#    Fuses ML anomaly score, KB similarity, correlation signal and existing
#    risk score into a single P(attack | evidence) posterior probability.
# ──────────────────────────────────────────────────────────────────────────────

class BayesianDecisionEngine:
    """
    Research-grade Bayesian Inference using Log-Odds and Signal Calibration.
    Avoids weighted sums; uses physical Likelihood Ratios (LR).
    """
    def __init__(self, base_prior: float = 0.02):
        self._lock = threading.RLock()
        self._base_prior = base_prior
        # History for dynamic prior P(Attack)
        self._outcome_window = deque(maxlen=2000) 
        
        # Decision thresholds (posterior probability)
        self._thresholds = {
            "BLOCK": 0.98,
            "THROTTLE": 0.88,
            "HONEYPOT": 0.75,
            "EYES_ON": 0.55
        }
        self._threshold_perf = {"fp": deque(maxlen=100), "fn": deque(maxlen=100)}

    def get_log_prior(self) -> float:
        """Computes ln( P(A) / P(~A) ) from rolling history."""
        with self._lock:
            if not self._outcome_window:
                p = self._base_prior
            else:
                # Laplace smoothed frequency
                p = (sum(self._outcome_window) + 1) / (len(self._outcome_window) + 50)
            return math.log(p / (1.0 - p))

    def fuse(
        self,
        ml_anomaly_prob: float,
        kb_similarity: float,
        cross_ip_correlation: float,
        deterministic_risk_score: float,
        is_trusted_user: bool = False
    ) -> dict:
        """
        Unified Decision Authority: Per-request Bayesian Evidence Fusion.
        Implements Progressive Defense Strategy.
        """
        # 0. Safety Override: Never block trusted users unless risk is extreme
        if is_trusted_user and deterministic_risk_score < 90:
            return {"action": "PASS", "posterior_prob": 0.01, "confidence": 1.0}

        # 1. Prior Log-Odds
        log_prior = self.get_log_prior()
        total_log_odds = log_prior

        # 2. ML Signal Likelihood Ratio (Non-linear calibration)
        ml_lr_log = 12.0 * (ml_anomaly_prob - 0.55)
        total_log_odds += ml_lr_log

        # 3. KB Similarity Signal (Long-term Memory)
        kb_lr_log = 0.0
        if kb_similarity > 0.3:
            kb_lr_log = -6.0 * math.log(1.0001 - kb_similarity) - 3.0
            total_log_odds += kb_lr_log

        # 4. Correlation Signal (Botnets/Distributed attacks)
        corr_lr_log = 0.0
        if cross_ip_correlation > 0.4:
            corr_lr_log = -5.0 * math.log(1.0001 - cross_ip_correlation) - 2.5
            total_log_odds += corr_lr_log

        # 5. Risk Engine (Deterministic Heuristics)
        # Actively dampens heuristics to prevent FP spikes from simple rate limits
        risk_norm = deterministic_risk_score / 100.0
        risk_lr_log = 6.0 * (risk_norm - 0.65) 
        total_log_odds += risk_lr_log

        # 6. Final Decision Calculation (Safe sigmoid)
        try:
            posterior_prob = 1.0 / (1.0 + math.exp(-max(-20, min(20, total_log_odds))))
        except Exception:
            posterior_prob = 1.0 if total_log_odds > 0 else 0.0

        confidence = abs(posterior_prob - 0.5) * 2.0
        action = self._determine_action(posterior_prob)

        return {
            "posterior_prob": round(posterior_prob, 5),
            "action": action,
            "confidence": round(confidence, 4),
            "evidence": {
                "total_log_odds": round(total_log_odds, 3)
            }
        }

    def update_prior(self, is_attack: bool):
        """Update historical feedback for the dynamic prior."""
        with self._lock:
            self._outcome_window.append(1 if is_attack else 0)

    def _determine_action(self, p: float) -> str:
        with self._lock:
            if p >= self._thresholds["BLOCK"]: return "BLOCK"
            if p >= self._thresholds["THROTTLE"]: return "THROTTLE_AND_CHALLENGE"
            if p >= self._thresholds["HONEYPOT"]: return "DIVERT_TO_HONEYPOT"
            if p >= self._thresholds["EYES_ON"]: return "ELEVATE_LOGGING"
            return "PASS"

    def adjust_thresholds(self, false_positive_rate: float, false_negative_rate: float):
        """
        Dynamically adjust thresholds based on observed FP/FN rates.
        Called by EvolutionController after each confirmed outcome.
        """
        with self._threshold_lock:
            # High FP rate → raise threshold (be less aggressive)
            if false_positive_rate > 0.10:
                self._block_threshold = min(0.99, self._block_threshold + 0.005)
            # High FN rate → lower threshold (be more aggressive)
            elif false_negative_rate > 0.10:
                self._block_threshold = max(0.85, self._block_threshold - 0.005)

    def get_thresholds(self) -> dict:
        return {
            "block": self._block_threshold,
            "throttle": self._throttle_threshold,
            "honeypot": self._honeypot_threshold,
        }

    def _action(self, prob: float) -> str:
        if prob >= self._block_threshold:
            return "BLOCK"
        elif prob >= self._throttle_threshold:
            return "THROTTLE_AND_CHALLENGE"
        elif prob >= self._honeypot_threshold:
            return "DIVERT_TO_HONEYPOT"
        elif prob >= 0.50:
            return "ELEVATE_LOGGING"
        return "PASS"

    @staticmethod
    def _calibrate_lr(p: float, slope: float, midpoint: float) -> float:
        """Sigmoid-shaped LR: LR=1 at p=midpoint, grows as p→1."""
        x = slope * (p - midpoint)
        if x >= 0:
            sig = 1.0 / (1.0 + math.exp(-x))
        else:
            z = math.exp(x)
            sig = z / (1.0 + z)
        return max(0.05, sig / 0.5)  # LR is scaled so sig(midpoint)≈1


# ──────────────────────────────────────────────────────────────────────────────
# 6. EvolutionController
#    Orchestrates the feedback loop:
#      honeypot confirmation → KB update → generalization → rule injection
#      → anomaly detector retrain → threshold adjustment
# ──────────────────────────────────────────────────────────────────────────────

class EvolutionController:
    """
    Orchestrates the Feedback loop: Attack -> Honeypot -> Label -> Store -> Retrain.
    """

    def __init__(
        self,
        anomaly_detector: UnsupervisedAnomalyDetector,
        knowledge_base: VectorKnowledgeBase,
        generalizer: PolymorphicPatternGeneralizer,
        bayesian_engine: BayesianDecisionEngine,
    ):
        self._detector = anomaly_detector
        self._kb = knowledge_base
        self._generalizer = generalizer
        self._bayes = bayesian_engine

        self._attack_pool: List[str] = []            
        self._fp_outcomes: deque = deque(maxlen=400) # True Positive / False Positive tracking
        self._fn_outcomes: deque = deque(maxlen=100) # False Negative tracking
        self._last_retrain = time.time()
        self._lock = threading.RLock()
        self._rule_injector = None  

        logger.info("[Evolution] Controller initialized.")

    def register_rule_injector(self, fn):
        """Register a callback for dynamic rule injection into SelfHealingEngine."""
        self._rule_injector = fn

    def handle_confirmed_attack(
        self,
        ip: str,
        payload: str,
        behavior_embedding: np.ndarray,
        features: dict,
        attack_type: str = "CONFIRMED_THREAT",
        matched_rules: List[str] = None
    ):
        """
        Triggered ONLY when a threat is confirmed via deception (Honeypot).
        This is the ONLY source for attack-labeled training data.
        """
        try:
            with self._lock:
                # 1. Update Bayesian Prior History
                self._bayes.update_prior(is_attack=True)

                # 2. Add to Vector Memory
                self._kb.memorize(behavior_embedding, {
                    "ip": ip,
                    "type": attack_type,
                    "payload_hash": hashlib.sha256(payload.encode()).hexdigest()[:16],
                    "confirmed_at": time.time()
                })

                # 3. Label for Anomaly Retraining (Safety: is_attack=True)
                self._detector.feed_label(features, is_attack=True)
                self._fp_outcomes.append(True)

                # 4. Update Rule Effectiveness
                if matched_rules:
                    from database import update_rule_effectiveness
                    for rule in matched_rules:
                        update_rule_effectiveness(rule, is_true_positive=True)

                # 4. Pattern Buffer for Generalization
                if payload and len(payload) > 10:
                    self._attack_pool.append(payload)

                # 5. Controlled Evolution (Retraining conditions)
                now = time.time()
                if now - self._last_retrain > RETRAIN_COOLDOWN:
                    if len(self._attack_pool) >= EVOLUTION_POOL_MIN:
                        # Ensure data diversity before retraining to avoid overfitting
                        if self._check_diversity(self._attack_pool):
                            threading.Thread(target=self._evolve, daemon=True).start()
                            self._last_retrain = now
        except Exception as e:
            logger.error(f"[Evolution] Attack handling failed: {e}")

    def handle_confirmed_normal(self, features: dict):
        """
        Label for normal retraining. 
        Safety: Only marking as 'trusted' if it passed significant duration without issues.
        """
        try:
            with self._lock:
                self._bayes.update_prior(is_attack=False)
                self._detector.feed_label(features, is_attack=False, trusted=True)
                self._fp_outcomes.append(False)
        except Exception as e:
            logger.error(f"[Evolution] Normal handling failed: {e}")

    def handle_correction(self, features: dict, was_actually_attack: bool, matched_rules: List[str] = None):
        """
        Handles manual or system-triggered corrections of defense decisions.
        Adjusts rule effectiveness, Bayesian prior, and ML buffers.
        """
        try:
            from database import update_rule_effectiveness
            with self._lock:
                # 0. Core state updates
                self._bayes.update_prior(is_attack=was_actually_attack)
                self._detector.feed_label(features, is_attack=was_actually_attack, trusted=not was_actually_attack)
                
                # 1. Memory correction (Vector Knowledge Base)
                # If we incorrectly thought it was an attack, remove it from memory.
                if not was_actually_attack:
                    # Regenerate embedding to match search logic
                    emb = build_behavioral_embedding(features)
                    self._kb.remove(emb)
                
                # 2. Rule effectiveness updates
                if matched_rules:
                    for rule in matched_rules:
                        update_rule_effectiveness(rule, is_true_positive=was_actually_attack)
                
                # 3. FP/FN tracking updates
                if was_actually_attack:
                    self._fn_outcomes.append(True)
                else:
                    self._fp_outcomes.append(False)

                logger.info(f"[Evolution] Feedback loop: Corrected decision for {features.get('ip')}. Threat: {was_actually_attack}")
        except Exception as e:
            logger.error(f"[Evolution] Correction failed: {e}")

    def _evolve(self):
        """Core evolution step: generalize → inject → retrain → save."""
        with self._lock:
            pool = list(self._attack_pool)
            self._attack_pool = []
        
        if not pool: return

        # 1. Generalized Rule Generation with Validation
        new_rules = self._generalizer.generalize(pool)
        if self._rule_injector and new_rules:
            for rule in new_rules:
                if rule.get("confidence", 0) > 0.6: # Safety threshold
                    try:
                        self._rule_injector(
                            name=f"Evolve_{hashlib.md5(rule['pattern'].encode()).hexdigest()[:8]}",
                            pattern=rule["pattern"],
                            severity=rule["severity"],
                            description=rule["description"]
                        )
                    except Exception as e:
                        logger.error(f"[Evolution] Rule injection failed: {e}")
        
        # 2. ML model retrain (already has its own internal cooldown/safety)
        self._detector.retrain()

        # 3. Save Knowledge Base to disk (Background)
        threading.Thread(target=self._kb.save, daemon=True).start()
        
        # 4. Periodic threshold tuning
        self._update_thresholds()
        
        logger.info(f"[Evolution] Completed cycle for {len(pool)} patterns. Thresholds tuned.")

    # ── Private ────────────────────────────────────────────────────────────

    @staticmethod
    def _check_diversity(pool: List[str]) -> bool:
        """Heuristic check to ensure we aren't retraining on the same single payload."""
        if len(pool) < 5: return False
        unique_payloads = len(set(pool))
        return (unique_payloads / len(pool)) > 0.4

    def _update_thresholds(self):
        """Recompute FP/FN rates and adjust Bayesian thresholds."""
        outcomes = list(self._fp_outcomes)
        if len(outcomes) < 20:
            return
        fp_rate = sum(1 for x in outcomes if not x) / len(outcomes)
        fn_rate = len(self._fn_outcomes) / max(len(outcomes), 1)
        self._bayes.adjust_thresholds(fp_rate, fn_rate)
        logger.info(f"[Evolution] Thresholds adjusted. FP={fp_rate:.2%}, FN={fn_rate:.2%}")


# ──────────────────────────────────────────────────────────────────────────────
# Behavioral Embedding Generator
# Converts BehaviorAnalyzer feature dict → 64-dim float vector
# (no external ML model download required)
# ──────────────────────────────────────────────────────────────────────────────

def build_behavioral_embedding(features: dict, payload: str = "") -> np.ndarray:
    """
    Converts a BehaviorAnalyzer feature dict + payload string into a
    64-dimensional behavioral embedding vector.

    The first 12 dims are the structured feature vector.
    Dims 12–63 are a lightweight structural n-gram hash of the payload,
    providing lexical similarity matching without a neural model.
    """
    # ── 12 structured dims ──
    freq = features.get("frequency", {})
    fail = features.get("failure", {})
    patt = features.get("pattern", {})
    payl = features.get("payload", {})
    sess = features.get("session", {})
    base = features.get("baseline_deviation", {})

    structured = np.array([
        min(freq.get("requests_in_window", 0), 200) / 200.0,
        1.0 if freq.get("burst_detected") else 0.0,
        min(fail.get("failure_rate", 0.0), 1.0),
        min(fail.get("consecutive_failures", 0), 20) / 20.0,
        min(patt.get("unique_endpoints", 0), 50) / 50.0,
        min(patt.get("sensitive_hits", 0), 10) / 10.0,
        1.0 if patt.get("scan_pattern") else 0.0,
        min(len(payl.get("current_flags", [])), 5) / 5.0,
        min(sess.get("unique_user_agents", 0), 10) / 10.0,
        min(freq.get("acceleration", 1.0), 20.0) / 20.0,
        1.0 if patt.get("enumeration_detected") else 0.0,
        min(sess.get("unique_sessions", 0), 10) / 10.0,
    ], dtype=np.float64)

    # ── 52 payload lexical dims via character bi-gram hashing ──
    payload_vec = np.zeros(52, dtype=np.float64)
    if payload:
        pl = payload.lower()[:512]
        for i in range(len(pl) - 1):
            bigram = pl[i:i+2]
            bucket = (hash(bigram) & 0x7fffffff) % 52
            payload_vec[bucket] += 1.0
        pmax = payload_vec.max()
        if pmax > 0:
            payload_vec /= pmax

    embedding = np.concatenate([structured, payload_vec])
    norm = np.linalg.norm(embedding)
    return embedding / (norm + 1e-12)


# ──────────────────────────────────────────────────────────────────────────────
# Module-level singleton factory
# ──────────────────────────────────────────────────────────────────────────────

_instances: dict = {}
_init_lock = threading.Lock()


def get_intelligence_suite() -> dict:
    """
    Returns a dict of singleton instances of all advanced intelligence components.
    Thread-safe; safe to call multiple times.

    Returns:
        {
          "anomaly":    UnsupervisedAnomalyDetector,
          "kb":         VectorKnowledgeBase,
          "generalizer":PolymorphicPatternGeneralizer,
          "correlator": CrossIPThreatCorrelator,
          "bayes":      BayesianDecisionEngine,
          "evolution":  EvolutionController,
        }
    """
    global _instances
    with _init_lock:
        if not _instances:
            anomaly = UnsupervisedAnomalyDetector()
            kb = VectorKnowledgeBase(dim=EMBEDDING_DIM)
            generalizer = PolymorphicPatternGeneralizer()
            correlator = CrossIPThreatCorrelator()
            bayes = BayesianDecisionEngine()
            evolution = EvolutionController(anomaly, kb, generalizer, bayes)
            _instances = {
                "anomaly": anomaly,
                "kb": kb,
                "generalizer": generalizer,
                "correlator": correlator,
                "bayes": bayes,
                "evolution": evolution,
            }
            logger.info("[Intelligence] Full suite initialized.")
    return _instances
