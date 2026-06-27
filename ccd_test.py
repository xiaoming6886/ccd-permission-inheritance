"""CCD Delegation Operator — Python Test Suite"""
from typing import Set, Tuple, Dict, List

# === Type Aliases ===
Capability = str
Constraint = str
AgentState = Tuple[Set[Capability], Set[Constraint]]

BLOCKED_BY: Dict[Constraint, Set[Capability]] = {
    'plan_mode': {'edit', 'write'},
    'bash_deny': {'bash'},
    'edit_deny': {'edit', 'write'},
}


def resolve_blocked(constraints: Set[Constraint]) -> Set[Capability]:
    blocked: Set[Capability] = set()
    for c in constraints:
        if c.startswith('max_depth:'):
            blocked.add('task')
        elif c in BLOCKED_BY:
            blocked.update(BLOCKED_BY[c])
    return blocked


def effective_permissions(
    caps: Set[Capability], 
    constraints: Set[Constraint], 
    depth: int = 0
) -> Set[Capability]:
    blocked = resolve_blocked(constraints)
    for c in constraints:
        if c.startswith('max_depth:'):
            limit = int(c.split(':')[1])
            if depth >= limit:
                blocked.add('task')
    return caps - blocked


def delegate(
    parent_caps: Set[Capability],
    parent_constraints: Set[Constraint],
    grants: Set[Capability],
    restrictions: Set[Constraint],
    parent_depth: int = 0,
) -> dict:
    """CCD Delegation Operator: C_c = C_p ∩ G, K_c = K_p ∪ R"""
    child_caps = parent_caps & grants
    child_constraints = parent_constraints | restrictions
    child_depth = parent_depth + 1
    violations: List[str] = []

    # Axiom 1: Non-Escalation
    if not (child_caps <= parent_caps):
        violations.append('AXIOM-1: Non-Escalation violated')

    # Axiom 2: Constraint Monotonicity
    if not (parent_constraints <= child_constraints):
        violations.append('AXIOM-2: Constraint Monotonicity violated')

    # Axiom 3: Effective Delegation
    child_eff = effective_permissions(child_caps, child_constraints, child_depth)
    if len(child_eff) == 0:
        violations.append('AXIOM-3: No effective permissions')

    # Grant validity check
    if not (grants <= parent_caps):
        violations.append(f'INVALID GRANT: unowned {grants - parent_caps}')

    return {
        'caps': child_caps,
        'constraints': child_constraints,
        'depth': child_depth,
        'effective': child_eff,
        'valid': len(violations) == 0,
        'violations': violations,
    }


# ============================================================
# TEST SUITE
# ============================================================

def test_plan_mode_bypass():
    """#6527: Plan mode constraint must propagate to subagent"""
    plan_caps = {'edit', 'write', 'bash', 'read', 'task'}
    plan_cons = {'plan_mode'}
    child = delegate(plan_caps, plan_cons, {'edit', 'write', 'bash', 'read'}, set())
    can_edit = 'edit' in child['effective']
    assert not can_edit, f"Subagent can edit despite plan_mode! eff={child['effective']}"
    assert child['valid'], f"Violations: {child['violations']}"


def test_bash_deny_bypass():
    """#7474: bash:deny must propagate to subagent"""
    caps = {'edit', 'bash', 'read', 'task'}
    cons = {'bash_deny', 'edit_deny'}
    child = delegate(caps, cons, {'bash', 'read'}, set())
    can_bash = 'bash' in child['effective']
    assert not can_bash, f"Subagent can bash despite bash_deny! eff={child['effective']}"


def test_commander_worker():
    """#26700: Commander constraints should not erase worker's allowed capabilities
    
    Commander: has {read, edit, bash, task}, constraint {edit_deny}
    Worker gets: {read, edit, bash} as grant
    Expected: Worker can read and bash, but NOT edit (edit_deny inherited)
    """
    commander_caps = {'read', 'edit', 'bash', 'task'}
    commander_cons = {'edit_deny'}
    worker = delegate(commander_caps, commander_cons, {'read', 'edit', 'bash'}, set())
    
    w_read = 'read' in worker['effective']
    w_bash = 'bash' in worker['effective']
    w_edit = 'edit' in worker['effective']
    
    assert w_read, f"Worker lost read! eff={worker['effective']}"
    assert w_bash, f"Worker lost bash! eff={worker['effective']}"
    assert not w_edit, f"Worker can edit despite edit_deny! eff={worker['effective']}"
    assert worker['valid'], f"Violations: {worker['violations']}"


def test_nested_delegation():
    """Axiom 4: Transitive Soundness in nested delegation chain
    
    Root: {edit,bash,read,task} + {plan_mode}
    -> L1: same + no extra constraints
    -> L2: {bash,read} + {bash_deny}
    Expected: L2 effective = {read} (plan_mode blocks edit+write, bash_deny blocks bash)
    """
    root_caps = {'edit', 'bash', 'read', 'task'}
    root_cons = {'plan_mode'}
    
    l1 = delegate(root_caps, root_cons, {'edit', 'bash', 'read', 'task'}, set())
    l2 = delegate(l1['caps'], l1['constraints'], {'bash', 'read'}, {'bash_deny'}, l1['depth'])
    
    assert l2['effective'] == {'read'}, f"Expected {{read}}, got {l2['effective']}"
    assert l2['valid'], f"Violations: {l2['violations']}"


def test_grant_unowned():
    """Cannot grant capabilities the parent doesn't have"""
    child = delegate({'task'}, set(), {'edit', 'bash'}, set())
    assert not child['valid'], f"Should be invalid: {child['violations']}"
    assert child['caps'] == set(), f"Child should have empty caps, got {child['caps']}"


def test_fully_blocked():
    """Axiom 3 boundary: fully blocked parent cannot delegate useful work"""
    child = delegate({'edit', 'bash'}, {'plan_mode', 'bash_deny'}, {'edit', 'bash'}, set())
    assert not child['valid'], f"Should fail: all caps blocked"
    assert len(child['effective']) == 0


def test_no_constraints_no_problem():
    """Unconstrained parent delegates normally"""
    child = delegate({'edit', 'bash', 'read'}, set(), {'edit', 'bash'}, set())
    assert child['valid'], f"Should be valid: {child['violations']}"
    assert child['effective'] == {'edit', 'bash'}


# ============================================================
# RUN
# ============================================================

if __name__ == '__main__':
    tests = [
        ('#6527 Plan Mode Bypass', test_plan_mode_bypass),
        ('#7474 bash:deny Bypass', test_bash_deny_bypass),
        ('#26700 Commander+Worker', test_commander_worker),
        ('Axiom 4 Nested Delegation', test_nested_delegation),
        ('Grant Unowned Check', test_grant_unowned),
        ('Fully Blocked Boundary', test_fully_blocked),
        ('Unconstrained Normal', test_no_constraints_no_problem),
    ]
    
    passed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS: {name}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL: {name}")
            print(f"  {e}")
        except Exception as e:
            print(f"ERROR: {name}")
            print(f"  {e}")
    
    print(f"\n=== {passed}/{len(tests)} PASSED ===")
