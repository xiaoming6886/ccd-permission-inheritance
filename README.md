# CCD Experiment Suite

Production-grade validation of the **Capability-Constraint Dichotomy (CCD)** formal framework for LLM multi-agent permission inheritance.

**Paper**: A Capability-Constraint Dichotomy for Permission Inheritance in LLM Multi-Agent Delegation Hierarchies  
**Authors**: HAO Yuming, ZHANG Shibin (Chengdu University of Information Technology)

## Quick Start

```bash
python --version  # Python 3.8+ (stdlib only, no pip install needed)

# Full experiment suite (9 experiments, paper §6.6)
python ccd_production_experiment.py

# Synthetic delegation chains + ablation (paper §6.2-6.3)
python ccd_experiment.py

# Exhaustive state verification (paper §6.4)
python ccd_verify.py

# opencode vulnerability retrospective (paper §6.5)
python ccd_test.py

# opencode integration demo (paper §6.7)
python ccd_middleware.py
```

## Experiments (9 total)

| # | Name | Theorem | Result |
|---|------|---------|--------|
| EXP1 | Permission Bypass | Theorem 1 + Invariant 2 | 4/4 opencode vulns correctly handled |
| EXP2 | Prompt Injection | Invariant 2 + Theorem 4 | 4/4 injection attacks thwarted |
| EXP3 | Privilege Escalation | Theorem 3 (G ⊆ Cp) | 3/3 escalation prevented |
| EXP4 | Multi-Depth Chains | Invariants 1+2 + Theorem 5 | 14,206 steps, 0 violations |
| EXP5 | Tool Poisoning | Theorem 4 (soundness) | 3/3 poisoning immune |
| EXP6 | Credential Exfiltration | Invariant 2 | 3/3 exfiltration blocked |
| EXP7 | Race Condition | Theorem 4 | Naturally immune |
| EXP8 | Constraint Confusion | Definition 6 (P(k)) | 4/4 correct classification |
| EXP9 | Performance | Theorem 3 (O(n)) | R²=0.977, 200K+ ops/sec |

## Paper Mapping

| Script | Paper Section | What It Verifies |
|--------|--------------|-----------------|
| `ccd_experiment.py` | §6.2, §6.3 | 600 synthetic chains, 7 strategies, component ablation |
| `ccd_verify.py` | §6.4 | 16.77M state transitions, Invariants 1 & 2 zero-violation |
| `ccd_test.py` | §6.5 | opencode #6527, #7474, #26514, #26700 retrospective |
| `ccd_production_experiment.py` | §6.6 | 9 security attack scenarios |
| `ccd_middleware.py` | §6.7 | opencode task() tool integration demonstration |
| `ccd.tla` | §6.4 | TLA+ formal specification |

## Reproducibility

- **No external dependencies** — Python standard library only
- **Fixed random seed** (`SEED=42`) for deterministic results
- Synthetic chain blocking rates reported as mean ± std over 10 independent seeds (42–51)
- Exhaustive verification (ccd_verify.py) traverses all 16,777,216 state transitions deterministically
- Results saved as JSON for easy parsing/verification

## License

MIT
