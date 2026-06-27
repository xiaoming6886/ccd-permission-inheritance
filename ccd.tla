---------------------------- MODULE CCD ----------------------------
\* CCD Delegation Model — TLA+ Specification
\* Verifies Invariant 1 (Capability Non-Escalation) and
\*          Invariant 2 (Constraint Monotonicity for propagatable constraints)

EXTENDS Naturals, FiniteSets, Sequences

\* === CONSTANTS ===
\* Caps: set of all possible capability types
\* Cons: set of all possible constraint types
\* Propagatable: subset of Cons that MUST propagate through delegation
\* BlockedBy[c]: set of capabilities blocked by constraint c

CONSTANTS Caps, Cons, Propagatable, BlockedBy
ASSUME Propagatable \subseteq Cons

\* === VARIABLES ===
\* caps: current agent capabilities
\* constraints: current agent constraints
\* step: delegation depth counter

VARIABLES caps, constraints, step

\* === TYPE INVARIANT ===
TypeOK ==
  /\ caps \subseteq Caps
  /\ constraints \subseteq Cons
  /\ step \in Nat

\* === HELPERS ===
\* Effective permissions: capabilities minus blocked-by-constraints
Effective(c, k) ==
  c \ { x \in c : \E y \in k : x \in BlockedBy[y] }

IsPropagatable(k) == k \in Propagatable

\* === INITIAL STATE ===
Init ==
  /\ caps \in SUBSET Caps
  /\ constraints \in SUBSET Cons
  /\ step = 0

\* === CCD DELEGATION OPERATOR ===
\* Deleg(p, c, grants, restricts)
\* C_c = C_p \cap grants
\* K_c = {k in K_p : propagatable(k)} \cup restricts
CCDDelegate(grants, restricts) ==
  /\ grants \subseteq Caps
  /\ restricts \subseteq Cons
  /\ caps' = caps \cap grants
  /\ constraints' = ({k \in constraints : IsPropagatable(k)}) \cup restricts
  /\ step' = step + 1

\* === ABLATION: Homogeneous (no propagatable distinction) ===
HomogeneousDelegate(grants, restricts) ==
  /\ grants \subseteq Caps
  /\ restricts \subseteq Cons
  /\ caps' = caps \cap grants
  /\ constraints' = constraints \cup restricts
  /\ step' = step + 1

\* === ABLATION: No constraint inheritance ===
NoConstraintsDelegate(grants, restricts) ==
  /\ grants \subseteq Caps
  /\ restricts \subseteq Cons
  /\ caps' = caps \cap grants
  /\ constraints' = restricts
  /\ step' = step + 1

\* === ABLATION: No capability intersection ===
NoCapIntersectDelegate(grants, restricts) ==
  /\ grants \subseteq Caps
  /\ restricts \subseteq Cons
  /\ caps' = caps
  /\ constraints' = ({k \in constraints : IsPropagatable(k)}) \cup restricts
  /\ step' = step + 1

\* === NEXT-STATE RELATION ===
\* Non-deterministically choose between strategies and grant/restrict values
Next ==
  \E grants \in SUBSET Caps :
    \E restricts \in SUBSET Cons :
      \/ CCDDelegate(grants, restricts)
      \/ HomogeneousDelegate(grants, restricts)
      \/ NoConstraintsDelegate(grants, restricts)
      \/ NoCapIntersectDelegate(grants, restricts)

\* === SPECIFICATION ===
Spec == Init /\ [][Next]_<<caps, constraints, step>>

\* === INVARIANTS TO VERIFY ===

\* Invariant 1: Capability Non-Escalation
\* After any delegation, child caps must be subset of parent caps
Invariant1 ==
  \A grants, restricts \in SUBSET Caps \X SUBSET Cons :
    (CCDDelegate(grants, restricts) => caps' \subseteq caps)

\* Invariant 2: Constraint Monotonicity (propagatable subset)
\* After CCD delegation, all propagatable parent constraints must be in child constraints
Invariant2 ==
  \A grants, restricts \in SUBSET Caps \X SUBSET Cons :
    (CCDDelegate(grants, restricts) => 
      ({k \in constraints : IsPropagatable(k)}) \subseteq constraints')

\* Invariant 2 for Homogeneous (must also hold)
Invariant2Homogeneous ==
  \A grants, restricts \in SUBSET Caps \X SUBSET Cons :
    (HomogeneousDelegate(grants, restricts) => constraints \subseteq constraints')

\* Safety: No strategy should produce empty caps AND empty constraints simultaneously
\* (child should always have at least something to work with, unless parent had nothing)
SafetyNoEmptyChild ==
  \A grants, restricts \in SUBSET Caps \X SUBSET Cons :
    (CCDDelegate(grants, restricts) /\ caps /= {} => 
      (caps' /= {} \/ constraints' /= {}))

\* === THEOREMS (derived, for documentation) ===

\* Theorem 3.1 (Impossibility): Any homogeneous model either violates Inv1 or Inv2
\* If caps' = caps /\ constraints' = constraints, then: (caps unchanged -> OK) but constraints unchanged
\* For non-empty Propagatable constraints: Inv2 violated after delegation where Propagatable constraints exist
Theorem3_1 ==
  \E c \in Cons : c \in Propagatable =>
    ~(\A grants, restricts \in SUBSET Caps \X SUBSET Cons :
        (HomogeneousDelegate(grants, restricts) /\ constraints /= {} =>
          Invariant2Homogeneous'))

\* Theorem 5 (Decidability): Delegation legality check is decidable
\* Check is: (grants \subseteq caps) /\ (caps' \subseteq caps) /\ (propagatable constraints inherited)
DelegationLegal(grants, restricts) ==
  /\ grants \subseteq caps
  /\ (caps \cap grants) \subseteq caps
  /\ ({k \in constraints : IsPropagatable(k)}) \subseteq 
     (({k \in constraints : IsPropagatable(k)}) \cup restricts)

====
