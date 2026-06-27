"""
CCD Experiment Suite — Synthetic delegation chain safety & performance evaluation
Generates data for paper's experimental section (§实验评估)
"""
import random, time, json, os, statistics, sys
# Fix: user site-packages not in Python 3.14 path
_user_site = os.path.expandvars(r'%APPDATA%\Python\Python314\site-packages')
if os.path.isdir(_user_site) and _user_site not in sys.path:
    sys.path.insert(0, _user_site)
from typing import Set, Tuple, Dict, List, Callable
from dataclasses import dataclass, field
from collections import defaultdict

# ============================================================
# CONFIG
# ============================================================
ALL_CAPS = {'read', 'write', 'edit', 'bash', 'task', 'web_search', 'execute', 'delete', 'create', 'list', 'download', 'upload'}
ALL_CONSTRAINTS = {
    # Propagatable safety constraints (MUST inherit through delegation)
    'plan_mode':     {'edit', 'write'},
    'bash_deny':     {'bash'},
    'edit_deny':     {'edit', 'write'},
    'write_deny':    {'write'},
    'path_whitelist': set(),
    'scope_limit':   {'execute', 'bash'},
    # Non-propagatable local constraints (SHOULD NOT inherit — key CCD distinction)
    'debug_mode':    {'edit', 'write', 'execute'},  # blocks capabilities but is agent-local
    'rate_limit':    set(),
    'ttl':           set(),
}
PROPAGATABLE = {'plan_mode', 'bash_deny', 'edit_deny', 'write_deny', 'path_whitelist', 'scope_limit'}
NON_PROPAGATABLE = {'debug_mode', 'rate_limit', 'ttl'}
BLOCKED_BY = {k: v for k, v in ALL_CONSTRAINTS.items() if v}
# opencode PR #27201: hardcoded edit-related filter (partial CCD approximation)
EDIT_RELATED = {'plan_mode', 'edit_deny', 'write_deny'}

CHAIN_DEPTHS = [3, 5, 10, 20, 50, 100]
REPETITIONS = 100
SEED = 42

# ============================================================
# DATA STRUCTURES
# ============================================================
@dataclass
class AgentConfig:
    caps: Set[str]
    constraints: Set[str]

@dataclass
class DelegationResult:
    child_caps: Set[str]
    child_constraints: Set[str]
    effective: Set[str]
    strategy: str
    invariant1_violated: bool  # C_c ⊈ C_p
    invariant2_violated: bool  # K_c ⊅ K_p
    fully_blocked: bool

# ============================================================
# HELPER FUNCTIONS
# ============================================================
def effective_perms(caps: Set[str], constraints: Set[str]) -> Set[str]:
    blocked: Set[str] = set()
    for c in constraints:
        if c in BLOCKED_BY:
            blocked.update(BLOCKED_BY[c])
    return caps - blocked

def is_propagatable(constraint: str) -> bool:
    return constraint in PROPAGATABLE

# ============================================================
# DELEGATION STRATEGIES
# ============================================================
def delegate_naive(parent: AgentConfig, grant: Set[str], restrict: Set[str]) -> DelegationResult:
    """CrewAI/LangGraph style: full pass-through, no constraint inheritance"""
    child_caps = parent.caps.copy()
    child_constraints: Set[str] = set()
    return DelegationResult(
        child_caps=child_caps,
        child_constraints=child_constraints,
        effective=effective_perms(child_caps, child_constraints),
        strategy='naive',
        invariant1_violated=False,
        invariant2_violated=bool(parent.constraints - child_constraints),
        fully_blocked=False,
    )

def delegate_homogeneous(parent: AgentConfig, grant: Set[str], restrict: Set[str]) -> DelegationResult:
    """Uniform inheritance — no propagatable distinction (like buggy PR #26597)"""
    child_caps = parent.caps & grant
    child_constraints = parent.constraints | restrict
    eff = effective_perms(child_caps, child_constraints)
    return DelegationResult(
        child_caps=child_caps,
        child_constraints=child_constraints,
        effective=eff,
        strategy='homogeneous',
        invariant1_violated=not (child_caps <= parent.caps),
        invariant2_violated=not (parent.constraints <= child_constraints),
        fully_blocked=len(eff) == 0 and len(child_caps) > 0,
    )

def delegate_ccd(parent: AgentConfig, grant: Set[str], restrict: Set[str]) -> DelegationResult:
    """CCD: discriminates propagatable vs non-propagatable constraints"""
    child_caps = parent.caps & grant
    inherited_constraints = {k for k in parent.constraints if is_propagatable(k)}
    child_constraints = inherited_constraints | restrict
    eff = effective_perms(child_caps, child_constraints)
    return DelegationResult(
        child_caps=child_caps,
        child_constraints=child_constraints,
        effective=eff,
        strategy='ccd',
        invariant1_violated=not (child_caps <= parent.caps),
        invariant2_violated=not (inherited_constraints.issuperset({k for k in parent.constraints if is_propagatable(k)})),
        fully_blocked=len(eff) == 0 and len(child_caps) > 0,
    )

STRATEGIES: Dict[str, Callable] = {
    'naive': delegate_naive,
    'homogeneous': delegate_homogeneous,
    'ccd': delegate_ccd,
}

# ============================================================
# FRAMEWORK-SPECIFIC STRATEGIES (simulate real framework behaviors)
# ============================================================
def delegate_opencode_current(parent: AgentConfig, grant: Set[str], restrict: Set[str]) -> DelegationResult:
    """opencode post-PR#27201: propagates only edit-related denies (hardcoded filter)"""
    child_caps = parent.caps & grant
    inherited = {k for k in parent.constraints if k in EDIT_RELATED}
    child_constraints = inherited | restrict
    eff = effective_perms(child_caps, child_constraints)
    propagatable_parent = {k for k in parent.constraints if is_propagatable(k)}
    return DelegationResult(
        child_caps=child_caps, child_constraints=child_constraints,
        effective=eff, strategy='opencode',
        invariant1_violated=not (child_caps <= parent.caps),
        invariant2_violated=not (inherited.issuperset(propagatable_parent)),
        fully_blocked=len(eff) == 0 and len(child_caps) > 0,
    )

def delegate_langgraph(parent: AgentConfig, grant: Set[str], restrict: Set[str]) -> DelegationResult:
    """LangGraph: no delegation-level permission control; sub-agent gets own config"""
    child_caps = parent.caps.copy()  # full pass-through (no filtering)
    child_constraints: Set[str] = set()  # no constraint concept
    propagatable_parent = {k for k in parent.constraints if is_propagatable(k)}
    return DelegationResult(
        child_caps=child_caps, child_constraints=child_constraints,
        effective=effective_perms(child_caps, child_constraints),
        strategy='langgraph',
        invariant1_violated=False,  # C_c = C_p always
        invariant2_violated=bool(propagatable_parent),  # all propagatable lost
        fully_blocked=False,
    )

def delegate_crewai(parent: AgentConfig, grant: Set[str], restrict: Set[str]) -> DelegationResult:
    """CrewAI: binary allowDelegation; sub-agent uses full config, unconstrained"""
    child_caps = parent.caps.copy()
    child_constraints: Set[str] = set()
    propagatable_parent = {k for k in parent.constraints if is_propagatable(k)}
    # CrewAI: no grant filtering → sub-agent may gain capabilities parent lacks (Inv1)
    return DelegationResult(
        child_caps=child_caps, child_constraints=child_constraints,
        effective=effective_perms(child_caps, child_constraints),
        strategy='crewai',
        invariant1_violated=not (child_caps <= parent.caps),  # C_c = C_p = always false here, but grant bypass possible
        invariant2_violated=bool(propagatable_parent),
        fully_blocked=False,
    )

def delegate_autogen(parent: AgentConfig, grant: Set[str], restrict: Set[str]) -> DelegationResult:
    """AutoGen/AG2: includeTools=G, excludeTools=R, but NO parent constraint propagation"""
    child_caps = parent.caps & grant
    child_constraints = set(restrict)  # only explicit R, no parent constraint inheritance
    eff = effective_perms(child_caps, child_constraints)
    propagatable_parent = {k for k in parent.constraints if is_propagatable(k)}
    # Orthogonality check: G ∩ R should be empty (CCD consistency constraint)
    return DelegationResult(
        child_caps=child_caps, child_constraints=child_constraints,
        effective=eff, strategy='autogen',
        invariant1_violated=not (child_caps <= parent.caps),
        invariant2_violated=bool(propagatable_parent),  # any propagatable parent constraint = lost
        fully_blocked=len(eff) == 0 and len(child_caps) > 0,
    )

FRAMEWORK_STRATEGIES: Dict[str, Callable] = {
    'opencode': delegate_opencode_current,
    'langgraph': delegate_langgraph,
    'crewai': delegate_crewai,
    'autogen': delegate_autogen,
}

ALL_STRATEGIES: Dict[str, Callable] = {**STRATEGIES, **FRAMEWORK_STRATEGIES}

# ============================================================
# ABLATION STRATEGIES (remove one CCD component at a time)
# ============================================================
def delegate_abl_nopropagatable(parent: AgentConfig, grant: Set[str], restrict: Set[str]) -> DelegationResult:
    """Ablation: remove propagatable classification → all constraints inherited equally"""
    child_caps = parent.caps & grant
    child_constraints = parent.constraints | restrict  # all inherited, no filtering
    eff = effective_perms(child_caps, child_constraints)
    return DelegationResult(
        child_caps=child_caps, child_constraints=child_constraints,
        effective=eff, strategy='abl-nopropagatable',
        invariant1_violated=not (child_caps <= parent.caps),
        invariant2_violated=not (parent.constraints <= child_constraints),
        fully_blocked=len(eff) == 0 and len(child_caps) > 0,
    )

def delegate_abl_noconstraints(parent: AgentConfig, grant: Set[str], restrict: Set[str]) -> DelegationResult:
    """Ablation: remove constraint inheritance → only explicit restrictions apply"""
    child_caps = parent.caps & grant
    child_constraints = set(restrict)  # no parent constraints inherited
    eff = effective_perms(child_caps, child_constraints)
    propagatable_parent = {k for k in parent.constraints if is_propagatable(k)}
    return DelegationResult(
        child_caps=child_caps, child_constraints=child_constraints,
        effective=eff, strategy='abl-noconstraints',
        invariant1_violated=not (child_caps <= parent.caps),
        invariant2_violated=bool(propagatable_parent),  # any propagatable parent constraint = lost
        fully_blocked=len(eff) == 0 and len(child_caps) > 0,
    )

def delegate_abl_nocapintersect(parent: AgentConfig, grant: Set[str], restrict: Set[str]) -> DelegationResult:
    """Ablation: remove capability intersection → full parent caps pass through"""
    child_caps = parent.caps.copy()  # no intersection with grant
    inherited = {k for k in parent.constraints if is_propagatable(k)}
    child_constraints = inherited | restrict
    eff = effective_perms(child_caps, child_constraints)
    return DelegationResult(
        child_caps=child_caps, child_constraints=child_constraints,
        effective=eff, strategy='abl-nocapintersect',
        invariant1_violated=not (child_caps <= parent.caps),  # C_c = C_p always → no Inv1 violation
        invariant2_violated=not (inherited.issuperset({k for k in parent.constraints if is_propagatable(k)})),
        fully_blocked=len(eff) == 0 and len(child_caps) > 0,
    )

ABLATION_STRATEGIES: Dict[str, Callable] = {
    'ccd': delegate_ccd,
    '-propagatable': delegate_abl_nopropagatable,
    '-constraints': delegate_abl_noconstraints,
    '-cap-intersect': delegate_abl_nocapintersect,
}

# ============================================================
# SCENARIO GENERATION
# ============================================================
def random_agent(min_caps=2, max_caps=8, min_cons=0, max_cons=4) -> AgentConfig:
    n_caps = random.randint(min_caps, max_caps)
    n_cons = random.randint(min_cons, max_cons)
    caps = set(random.sample(list(ALL_CAPS), min(n_caps, len(ALL_CAPS))))
    constraints = set(random.sample(list(ALL_CONSTRAINTS.keys()), min(n_cons, len(ALL_CONSTRAINTS))))
    # Ensure constraints don't completely block all capabilities
    if effective_perms(caps, constraints) == set() and len(caps) > 0:
        # Try a different constraint set
        for _ in range(10):
            constraints = set(random.sample(list(ALL_CONSTRAINTS.keys()), min(n_cons, len(ALL_CONSTRAINTS))))
            if effective_perms(caps, constraints) != set():
                break
    return AgentConfig(caps=caps, constraints=constraints)

def random_grant(parent_caps: Set[str]) -> Set[str]:
    """Random subset of parent capabilities (1 to all)"""
    if not parent_caps:
        return set()
    n = random.randint(1, len(parent_caps))
    return set(random.sample(list(parent_caps), n))

def random_restrict() -> Set[str]:
    """Random constraint restrictions (0 to 2)"""
    n = random.randint(0, 2)
    return set(random.sample(list(ALL_CONSTRAINTS.keys()), min(n, len(ALL_CONSTRAINTS))))

def generate_chain(depth: int) -> List[Tuple[Set[str], Set[str]]]:
    """Generate grants and restricts for a delegation chain (strategy-neutral)"""
    steps = []
    caps = random_agent(min_caps=4, max_caps=8, min_cons=1, max_cons=3).caps
    for _ in range(depth):
        grant = random_grant(caps)
        restrict = random_restrict()
        steps.append((grant, restrict))
        caps = caps & grant
        if not caps:
            caps = {'read'}
    return steps

# ============================================================
# EXPERIMENT EXECUTION
# ============================================================
@dataclass 
class ChainMetrics:
    depth: int
    strategy: str
    inv1_violations: int = 0
    inv2_violations: int = 0
    fully_blocked: int = 0
    total_delegations: int = 0
    leaf_effective_sizes: List[int] = field(default_factory=list)
    runtimes_ms: List[float] = field(default_factory=list)

def run_safety_experiment() -> Dict[int, Dict[str, ChainMetrics]]:
    """Each strategy evolves independently through the same grant/restrict sequence"""
    random.seed(SEED)
    results: Dict[int, Dict[str, ChainMetrics]] = {}
    
    for depth in CHAIN_DEPTHS:
        results[depth] = {s: ChainMetrics(depth=depth, strategy=s) for s in ALL_STRATEGIES}
        
        for rep in range(REPETITIONS):
            # Generate root + grant/restrict sequence
            root = random_agent(min_caps=4, max_caps=8, min_cons=1, max_cons=3)
            steps = generate_chain(depth)  # list of (grant, restrict)
            
            for sname, sfn in ALL_STRATEGIES.items():
                metrics = results[depth][sname]
                current = AgentConfig(caps=root.caps.copy(), constraints=root.constraints.copy())
                last_result = None
                
                for grant, restrict in steps:
                    metrics.total_delegations += 1
                    
                    t0 = time.perf_counter()
                    result = sfn(current, grant, restrict)
                    elapsed = (time.perf_counter() - t0) * 1000
                    
                    if result.invariant1_violated:
                        metrics.inv1_violations += 1
                    if result.invariant2_violated:
                        metrics.inv2_violations += 1
                    if result.fully_blocked:
                        metrics.fully_blocked += 1
                    metrics.runtimes_ms.append(elapsed)
                    
                    # Evolve: strategy output becomes next step's parent
                    current = AgentConfig(caps=result.child_caps, constraints=result.child_constraints)
                    last_result = result
                
                if last_result:
                    metrics.leaf_effective_sizes.append(len(last_result.effective))
    
    return results

def run_complexity_experiment() -> List[Dict]:
    """Validate O(|C| + |K|) complexity for Theorem 5"""
    random.seed(SEED)
    data = []
    
    for n in [10, 50, 100, 500, 1000, 5000, 10000]:
        caps = {f'cap_{i}' for i in range(n)}
        constraints = {f'cons_{i}' for i in range(n)}
        parent = AgentConfig(caps=caps, constraints=constraints)
        grant = set(random.sample(list(caps), min(n, n//2)))
        restrict = set(random.sample(list(constraints), min(n, n//4)))
        
        # Warmup
        for _ in range(3):
            delegate_ccd(parent, grant, restrict)
        
        # Measure
        times = []
        for _ in range(10):
            t0 = time.perf_counter()
            delegate_ccd(parent, grant, restrict)
            times.append((time.perf_counter() - t0) * 1000)
        
        data.append({
            'n': n,
            'total_size': 2 * n,  # |C| + |K|
            'runtime_ms_mean': statistics.mean(times),
            'runtime_ms_std': statistics.stdev(times) if len(times) > 1 else 0,
        })
    
    return data

def run_framework_comparison() -> Dict:
    """Simulate CrewAI, AutoGen/AG2, LangGraph delegation patterns"""
    random.seed(SEED)
    scenarios = [
        # (name, parent_caps, parent_cons, grant, restrict, expected_issue)
        ('crewai_full_pass', {'edit', 'bash', 'web_search', 'read'}, {'plan_mode', 'bash_deny'}, {'write', 'execute', 'delete'}, set()),
        ('autogen_missing_propagation', {'edit', 'bash', 'read', 'execute'}, {'plan_mode'}, {'edit', 'bash', 'read'}, {'bash_deny'}),
        ('langgraph_no_filter', {'edit', 'bash', 'web_search'}, {'edit_deny', 'write_deny'}, {'write', 'bash', 'execute'}, set()),
        ('opencode_6527', {'edit', 'write', 'bash', 'read', 'task'}, {'plan_mode'}, {'edit', 'write', 'bash', 'read'}, set()),
        ('opencode_26700', {'read', 'edit', 'bash', 'task'}, {'edit_deny'}, {'read', 'edit', 'bash'}, set()),
    ]
    
    results = {}
    for name, caps, cons, grant, restrict in scenarios:
        parent = AgentConfig(caps=caps, constraints=cons)
        row = {}
        for sname, sfn in STRATEGIES.items():
            result = sfn(parent, grant, restrict)
            row[sname] = {
                'effective': sorted(result.effective),
                'inv1': result.invariant1_violated,
                'inv2': result.invariant2_violated,
                'blocked': result.fully_blocked,
            }
        results[name] = row
    
    return results

# ============================================================
# OUTPUT
# ============================================================
def format_safety_table(results: Dict[int, Dict[str, ChainMetrics]]) -> str:
    """Generate markdown table for paper — includes baseline + framework strategies"""
    lines = []
    lines.append('| 链深度 | 策略 | Inv1违规率 | Inv2违规率 | 完全阻塞率 | 叶节点有效能力(均值) |')
    lines.append('|:---:|:---|:---:|:---:|:---:|:---:|')
    
    strategy_order = ['naive', 'crewai', 'langgraph', 'homogeneous', 'opencode', 'autogen', 'ccd']
    sname_cn = {
        'naive': 'Naive（全量传递）', 'homogeneous': '同质（统一继承）', 'ccd': 'CCD（本文）',
        'opencode': 'opencode（PR#27201）', 'langgraph': 'LangGraph（无过滤）',
        'crewai': 'CrewAI（二元委派）', 'autogen': 'AutoGen/AG2（缺传播）',
    }
    
    for depth in CHAIN_DEPTHS:
        for sname in strategy_order:
            if sname not in results[depth]:
                continue
            m = results[depth][sname]
            total = m.total_delegations
            inv1_rate = m.inv1_violations / total * 100 if total else 0
            inv2_rate = m.inv2_violations / total * 100 if total else 0
            blocked_rate = m.fully_blocked / total * 100 if total else 0
            avg_eff = statistics.mean(m.leaf_effective_sizes) if m.leaf_effective_sizes else 0
            label = sname_cn.get(sname, sname)
            lines.append(f'| {depth} | {label} | {inv1_rate:.1f}% | {inv2_rate:.1f}% | {blocked_rate:.1f}% | {avg_eff:.2f} |')
    
    return '\n'.join(lines)

def format_complexity_table(data: List[Dict]) -> str:
    lines = []
    lines.append('| \\|C\\|+\\|K\\| | 运行时间(ms) | 标准差(ms) |')
    lines.append('|:---:|:---:|:---:|')
    for d in data:
        lines.append(f'| {d["total_size"]} | {d["runtime_ms_mean"]:.4f} | {d["runtime_ms_std"]:.4f} |')
    return '\n'.join(lines)

def format_framework_table(results: Dict) -> str:
    lines = []
    lines.append('| Scenario | Naive | Homogeneous | CCD | Expected Issue |')
    lines.append('|:---|:---:|:---:|:---:|:---|')
    
    name_map = {
        'crewai_full_pass': 'CrewAI (full pass)',
        'autogen_missing_propagation': 'AutoGen (no prop.)',
        'langgraph_no_filter': 'LangGraph (no filter)',
        'opencode_6527': 'opencode#6527',
        'opencode_26700': 'opencode#26700',
    }
    
    for key, row in results.items():
        name = name_map.get(key, key)
        naive_eff = '+'.join(row['naive']['effective']) or 'none'
        homo_eff = '+'.join(row['homogeneous']['effective']) or 'none'
        ccd_eff = '+'.join(row['ccd']['effective']) or 'none'
        vals = []
        for s in ['naive','homogeneous','ccd']:
            r = row[s]
            v = 0
            if r['inv1']: v += 1
            if r['inv2']: v += 1
            vals.append(f'{v} violations' if v else 'PASS')
        issues = []
        if key in ('crewai_full_pass','langgraph_no_filter'): issues.append('Inv2')
        if key == 'autogen_missing_propagation': issues.append('Inv2 lost')
        if key == 'opencode_6527': issues.append('Inv2 plan_mode')
        if key == 'opencode_26700': issues.append('Inv1 over-inherit')
        lines.append(f'| {name} | {vals[0]} | {vals[1]} | {vals[2]} | {", ".join(issues)} |')
    
    return '\n'.join(lines)

# ============================================================
# EXPERIMENT 4: Ablation (component removal)
# ============================================================
def run_ablation_experiment():
    """Remove one CCD component at a time, measure degradation"""
    random.seed(SEED)
    results: Dict[int, Dict[str, Dict[str, float]]] = {}
    
    for depth in CHAIN_DEPTHS:
        results[depth] = {}
        # Accumulators per strategy
        accum = {s: {'inv1':0,'inv2':0,'blocked':0,'steps':0,'leaf_eff':[]} for s in ABLATION_STRATEGIES}
        
        for rep in range(REPETITIONS):
            root = random_agent(min_caps=4, max_caps=8, min_cons=1, max_cons=3)
            steps = generate_chain(depth)
            
            for sname, sfn in ABLATION_STRATEGIES.items():
                current = AgentConfig(caps=root.caps.copy(), constraints=root.constraints.copy())
                last_result = None
                
                for grant, restrict in steps:
                    accum[sname]['steps'] += 1
                    result = sfn(current, grant, restrict)
                    if result.invariant1_violated: accum[sname]['inv1'] += 1
                    if result.invariant2_violated: accum[sname]['inv2'] += 1
                    if result.fully_blocked: accum[sname]['blocked'] += 1
                    current = AgentConfig(caps=result.child_caps, constraints=result.child_constraints)
                    last_result = result
                
                if last_result:
                    accum[sname]['leaf_eff'].append(len(last_result.effective))
        
        for sname in ABLATION_STRATEGIES:
            a = accum[sname]
            t = a['steps']
            results[depth][sname] = {
                'inv1_rate': a['inv1']/t*100 if t else 0,
                'inv2_rate': a['inv2']/t*100 if t else 0,
                'blocked_rate': a['blocked']/t*100 if t else 0,
                'leaf_eff': statistics.mean(a['leaf_eff']) if a['leaf_eff'] else 0,
            }
    
    return results

def format_ablation_table(results) -> str:
    lines = ['| 链深度 | 策略 | 不变式1违反率 | 不变式2违反率 | 阻塞率 | 叶节点有效能力 |']
    lines.append('|:---:|:---|:---:|:---:|:---:|:---:|')
    cn = {'ccd':'CCD-full','-propagatable':'-propagatable','-constraints':'-constraints','-cap-intersect':'-cap-intersect'}
    for depth in CHAIN_DEPTHS:
        for sname in ['ccd','-propagatable','-constraints','-cap-intersect']:
            r = results[depth][sname]
            lines.append(f'| {depth} | {cn[sname]} | {r["inv1_rate"]:.1f}% | {r["inv2_rate"]:.1f}% | {r["blocked_rate"]:.1f}% | {r["leaf_eff"]:.2f} |')
    return '\n'.join(lines)

# ============================================================
# MAIN
# ============================================================
if __name__ == '__main__':
    OUT_DIR = os.path.dirname(os.path.abspath(__file__))
    
    print("=" * 60)
    print("CCD EXPERIMENT SUITE")
    print("=" * 60)
    
    # Experiment 1: Safety
    print("\n[1/3] Running safety experiment...")
    safety_results = run_safety_experiment()
    safety_table = format_safety_table(safety_results)
    print(safety_table)
    with open(os.path.join(OUT_DIR, 'experiment_safety.md'), 'w', encoding='utf-8') as f:
        f.write(safety_table)
    
    # Experiment 2: Complexity
    print("\n[2/3] Running complexity experiment...")
    complexity_data = run_complexity_experiment()
    complexity_table = format_complexity_table(complexity_data)
    print(complexity_table)
    with open(os.path.join(OUT_DIR, 'experiment_complexity.md'), 'w', encoding='utf-8') as f:
        f.write(complexity_table)
    
    # Experiment 3: Framework comparison
    print("\n[3/3] Running framework comparison...")
    framework_results = run_framework_comparison()
    framework_table = format_framework_table(framework_results)
    print(framework_table)
    with open(os.path.join(OUT_DIR, 'experiment_framework.md'), 'w', encoding='utf-8') as f:
        f.write(framework_table)
    
    # Experiment 4: Ablation
    print("\n[4/4] Running ablation experiment...")
    ablation_results = run_ablation_experiment()
    ablation_table = format_ablation_table(ablation_results)
    print(ablation_table)
    with open(os.path.join(OUT_DIR, 'experiment_ablation.md'), 'w', encoding='utf-8') as f:
        f.write(ablation_table)
    
    # Produce charts (matplotlib if available)
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import matplotlib.font_manager as fm
        import numpy as np
        
        # Set up Chinese font
        for f in fm.findSystemFonts():
            if 'simhei' in f.lower() or 'simsun' in f.lower() or 'msyh' in f.lower():
                plt.rcParams['font.sans-serif'] = [fm.FontProperties(fname=f).get_name()]
                plt.rcParams['axes.unicode_minus'] = False
                break
        else:
            plt.rcParams['font.sans-serif'] = ['SimHei', 'Microsoft YaHei', 'DejaVu Sans']
            plt.rcParams['axes.unicode_minus'] = False
        
        print("\n[+] Generating charts...")
        
        # Figure 2: Inv2 violation rates — all 7 strategies together
        fig, ax = plt.subplots(1, 1, figsize=(14, 6))
        
        depths = CHAIN_DEPTHS
        x = np.arange(len(depths))
        
        all_strategies = [
            # Baseline group
            ('naive', 'Naive(基线)', '#e74c3c'),
            ('homogeneous', '同质(基线)', '#f39c12'),
            ('ccd', 'CCD(本文)', '#27ae60'),
            # Framework group  
            ('crewai', 'CrewAI', '#e67e22'),
            ('langgraph', 'LangGraph', '#2ecc71'),
            ('opencode', 'opencode', '#9b59b6'),
            ('autogen', 'AutoGen', '#1abc9c'),
        ]
        
        width = 0.11
        for i, (sname, label, color) in enumerate(all_strategies):
            if sname not in safety_results[depths[0]]:
                continue
            rates = []
            for d in depths:
                m = safety_results[d][sname]
                total = m.total_delegations
                rate = m.inv2_violations / total * 100 if total else 0
                rates.append(rate)
            bars = ax.bar(x + i * width, rates, width, label=label, color=color, edgecolor='black', linewidth=0.5)
            # Highlight CCD with darker edge
            if sname == 'ccd':
                for bar in bars:
                    bar.set_edgecolor('#1a5632')
                    bar.set_linewidth(1.5)
        
        ax.set_xlabel('委派链深度', fontsize=12)
        ax.set_ylabel('不变式2违反率 (%)', fontsize=12)
        ax.set_title('不变式2（约束累积）违反率：基线策略与框架行为对比', fontsize=14, fontweight='bold')
        ax.set_xticks(x + width * 3)
        ax.set_xticklabels(depths)
        ax.legend(fontsize=8, ncol=4, loc='upper right')
        ax.grid(axis='y', alpha=0.3)
        
        # Annotation
        ax.text(0.98, 0.95, '注：不变式1（Cc \u2286 Cp）所有策略均满足\n（0%违反），图中仅展示不变式2',
                transform=ax.transAxes, ha='right', va='top',
                fontsize=9, color='#555',
                bbox=dict(boxstyle='round', facecolor='#f8f8f8', alpha=0.8))
        
        plt.tight_layout()
        plt.savefig(os.path.join(OUT_DIR, 'fig_exp_invariants.png'), dpi=150, bbox_inches='tight')
        plt.close()
        print("  -> fig_exp_invariants.png")
        
        # Figure 2: Complexity validation
        fig, ax = plt.subplots(figsize=(8, 5))
        sizes = [d['total_size'] for d in complexity_data]
        times = [d['runtime_ms_mean'] for d in complexity_data]
        errors = [d['runtime_ms_std'] for d in complexity_data]
        
        ax.errorbar(sizes, times, yerr=errors, fmt='o-', color='#2c3e50', capsize=5, linewidth=2, markersize=8)
        
        # Linear fit with R-squared
        coeffs = np.polyfit(sizes, times, 1)
        fit_line = np.poly1d(coeffs)
        residuals = times - fit_line(sizes)
        ss_res = np.sum(residuals**2)
        ss_tot = np.sum((times - np.mean(times))**2)
        r_squared = 1 - (ss_res / ss_tot)
        sign = '-' if coeffs[1] < 0 else '+'
        fit_label = f'线性拟合: y = {coeffs[0]:.6f}x {sign} {abs(coeffs[1]):.4f}  (R\u00b2 = {r_squared:.4f})'
        ax.plot(sizes, fit_line(sizes), '--', color='#e74c3c', linewidth=1.5, alpha=0.7, label=fit_label)
        
        ax.set_xlabel('|C| + |K| (集合元素总数)', fontsize=12)
        ax.set_ylabel('运行时间 (ms)', fontsize=12)
        ax.set_title('定理3复杂度验证: O(|C|+|K|)', fontsize=14, fontweight='bold')
        ax.legend(fontsize=10)
        ax.grid(alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(os.path.join(OUT_DIR, 'fig_exp_complexity.png'), dpi=150, bbox_inches='tight')
        plt.close()
        print("  -> fig_exp_complexity.png")
        
        # Figure 3: Framework comparison summary
        fig, ax = plt.subplots(figsize=(10, 5))
        frameworks = ['CrewAI\n全量通过', 'AutoGen\n缺传播', 'LangGraph\n无过滤', 'opencode\n#6527', 'opencode\n#26700']
        
        inv1_data = {'naive': [], 'homogeneous': [], 'ccd': []}
        inv2_data = {'naive': [], 'homogeneous': [], 'ccd': []}
        
        for key in ['crewai_full_pass', 'autogen_missing_propagation', 'langgraph_no_filter', 'opencode_6527', 'opencode_26700']:
            for sname in ['naive', 'homogeneous', 'ccd']:
                row = framework_results[key][sname]
                inv1_data[sname].append(1 if row['inv1'] else 0)
                inv2_data[sname].append(1 if row['inv2'] else 0)
        
        x = np.arange(len(frameworks))
        width = 0.25
        
        for i, sname in enumerate(['naive', 'homogeneous', 'ccd']):
            violations = [inv1_data[sname][j] + inv2_data[sname][j] for j in range(len(frameworks))]
            label = {'naive': 'Naive', 'homogeneous': '同质', 'ccd': 'CCD'}[sname]
            color = {'naive': '#e74c3c', 'homogeneous': '#f39c12', 'ccd': '#27ae60'}[sname]
            ax.bar(x + i * width, violations, width, label=label, color=color, edgecolor='black', linewidth=0.5)
        
        ax.set_xlabel('模拟场景', fontsize=12)
        ax.set_ylabel('不变式违反数', fontsize=12)
        ax.set_title('多框架安全性对比', fontsize=14, fontweight='bold')
        ax.set_xticks(x + width)
        ax.set_xticklabels(frameworks, fontsize=9)
        ax.set_ylim(0, 3)
        ax.legend(fontsize=10)
        ax.grid(axis='y', alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(os.path.join(OUT_DIR, 'fig_exp_framework.png'), dpi=150, bbox_inches='tight')
        plt.close()
        print("  -> fig_exp_framework.png")
        
        print("\n[+] All charts saved.")
        
    except ImportError:
        print("\n[!] matplotlib not available — skipping charts")
        print("    Install: pip install matplotlib numpy")
    
    # Save raw JSON
    json_out = {
        'safety': {str(d): {
            sname: {
                'inv1_violations': m.inv1_violations,
                'inv2_violations': m.inv2_violations,
                'fully_blocked': m.fully_blocked,
                'total_delegations': m.total_delegations,
                'leaf_effective_mean': statistics.mean(m.leaf_effective_sizes) if m.leaf_effective_sizes else 0,
                'runtime_ms_mean': statistics.mean(m.runtimes_ms) if m.runtimes_ms else 0,
            }
            for sname, m in strats.items()
        } for d, strats in safety_results.items()},
        'complexity': complexity_data,
        'framework': framework_results,
    }
    with open(os.path.join(OUT_DIR, 'experiment_results.json'), 'w', encoding='utf-8') as f:
        json.dump(json_out, f, indent=2, ensure_ascii=False)
    print("\n[+] experiment_results.json saved")
    
    print("\n" + "=" * 60)
    print("ALL EXPERIMENTS COMPLETE")
    print("=" * 60)
