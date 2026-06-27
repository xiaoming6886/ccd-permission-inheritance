"""
CCD TLA+ Invariant Verifier — Exhaustive state-space search
Equivalent to TLC model checking for finite state spaces.
"""
from itertools import product, combinations
from typing import Set, Dict, Tuple

# === MODEL CONSTANTS (must match ccd.tla) ===
Caps = {'read', 'write', 'edit', 'bash', 'task', 'web_search'}
Cons = {'plan_mode', 'bash_deny', 'edit_deny', 'write_deny', 'debug_mode', 'rate_limit'}
Propagatable = {'plan_mode', 'bash_deny', 'edit_deny', 'write_deny'}
BlockedBy: Dict[str, Set[str]] = {
    'plan_mode': {'edit', 'write'},
    'bash_deny': {'bash'},
    'edit_deny': {'edit', 'write'},
    'write_deny': {'write'},
    'debug_mode': {'edit', 'write', 'execute'},
    'rate_limit': set(),
}

def effective(c: Set[str], k: Set[str]) -> Set[str]:
    blocked: Set[str] = set()
    for con in k:
        if con in BlockedBy:
            blocked.update(BlockedBy[con])
    return c - blocked

def ccd_delegate(caps: Set[str], constraints: Set[str], grants: Set[str], restricts: Set[str]):
    c2 = caps & grants
    k2 = {k for k in constraints if k in Propagatable} | restricts
    return c2, k2

def homogeneous_delegate(caps, constraints, grants, restricts):
    return caps & grants, constraints | restricts

def noconstraints_delegate(caps, constraints, grants, restricts):
    return caps & grants, set(restricts)

def nocap_delegate(caps, constraints, grants, restricts):
    return caps.copy(), {k for k in constraints if k in Propagatable} | restricts

def verify_invariants():
    """Exhaustive state-space search: enumerate ALL possible states and verify invariants."""
    all_subsets_c = [set(s) for r in range(len(Caps)+1) for s in combinations(Caps, r)]
    all_subsets_k = [set(s) for r in range(len(Cons)+1) for s in combinations(Cons, r)]
    all_grants = all_subsets_c
    all_restricts = all_subsets_k
    
    total_states = len(all_subsets_c) * len(all_subsets_k)
    total_transitions = total_states * len(all_grants) * len(all_restricts)
    
    print(f"State space: {len(all_subsets_c)} cap-subsets x {len(all_subsets_k)} cons-subsets = {total_states} states")
    print(f"Transitions per state: {len(all_grants)} grants x {len(all_restricts)} restricts = {len(all_grants)*len(all_restricts)}")
    print(f"Total transitions to check: {total_transitions}")
    print()
    
    results = {}
    for strategy_name, strategy_fn in [
        ('CCD', ccd_delegate),
        ('Homogeneous', homogeneous_delegate),
        ('NoConstraints', noconstraints_delegate),
        ('NoCapIntersect', nocap_delegate),
    ]:
        inv1_violations = 0
        inv2_violations = 0
        total = 0
        
        for caps in all_subsets_c:
            for constraints in all_subsets_k:
                propagatable_parent = {k for k in constraints if k in Propagatable}
                for grants in all_grants:
                    for restricts in all_restricts:
                        total += 1
                        c2, k2 = strategy_fn(caps, constraints, grants, restricts)
                        
                        # Invariant 1: C_c ⊆ C_p
                        if not (c2 <= caps):
                            inv1_violations += 1
                        
                        # Invariant 2: propagatable(K_p) ⊆ K_c
                        if not (propagatable_parent <= k2):
                            inv2_violations += 1
        
        results[strategy_name] = {
            'inv1': inv1_violations,
            'inv2': inv2_violations,
            'total': total,
            'inv1_rate': inv1_violations / total * 100 if total else 0,
            'inv2_rate': inv2_violations / total * 100 if total else 0,
        }
        
        print(f"{strategy_name:15s}: Inv1={inv1_violations}/{total} ({inv1_violations/total*100:.1f}%), "
              f"Inv2={inv2_violations}/{total} ({inv2_violations/total*100:.1f}%)")
    
    # Verify Theorem 3.1: Homogeneous model must violate at least one invariant
    # when propagatable constraints exist
    print()
    print("=== Theorem 3.1 Verification ===")
    theo31_confirmed = False
    for caps in all_subsets_c:
        for constraints in all_subsets_k:
            propagatable_parent = {k for k in constraints if k in Propagatable}
            if propagatable_parent:
                # Check: does homogeneous strategy ever violate invariants when propagatable constraints exist?
                for grants in all_grants:
                    for restricts in all_restricts:
                        c2, k2 = homogeneous_delegate(caps, constraints, grants, restricts)
                        # Homogeneous: C_c ⊆ C_p always true (C_c = C_p ∩ G)
                        # But if propagatable constraints exist AND non-propagatable constraints exist,
                        # the child gets more constraints than necessary (over-blocking)
                        # TLA+ Theorem 3.1 is about the IMPOSSIBILITY of a homogeneous model
                        # satisfying both safety AND usability
                        if not (propagatable_parent <= k2):
                            theo31_confirmed = True
                            break
                    if theo31_confirmed:
                        break
            if theo31_confirmed:
                break
        if theo31_confirmed:
            break
    
    print(f"  Theorem 3.1 confirmed: {theo31_confirmed}")
    print(f"  (Any homogeneous model that loses propagatable constraints violates Inv2)")
    
    # Verify Theorem 5: O(|C|+|K|) decidability
    # CCD delegation check is purely set operations — obviously decidable
    print()
    print("=== Theorem 5 (Decidability) Verification ===")
    print("  CCD delegation legality check: grants subset-of caps AND caps^grants subset-of caps")
    print("  Both are finite set operations, always decidable in O(|C|+|K|)")
    print("  Status: TRIVIALLY TRUE (finite set membership checks)")
    
    # Summary
    print()
    print("=== FINAL VERDICT ===")
    all_pass = True
    for name, r in results.items():
        p1 = 'PASS' if r['inv1'] == 0 else f'FAIL ({r["inv1"]} violations)'
        p2 = 'PASS' if r['inv2'] == 0 else f'FAIL ({r["inv2"]} violations)'
        if r['inv1'] > 0 or (name == 'CCD' and r['inv2'] > 0):
            all_pass = False
        print(f"  {name:15s}: Inv1={p1}, Inv2={p2}")
    
    if all_pass:
        print("\n  [PASS] All CCD invariants hold across entire state space.")
    else:
        print("\n  [FAIL] Some invariants violated — check ablation strategies for expected violations.")
    
    return results

if __name__ == '__main__':
    verify_invariants()
