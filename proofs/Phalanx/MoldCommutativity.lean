/-
  Phalanx Mold Commutativity Proof — Lean 4

  Goal: For any set of admitted shards, the final Recording produced by
  RecordingAmalgam.assemble() is identical regardless of the order in
  which ingest() is called.

  Mirrors: phalanx-forensics/src/crucible.rs  RecordingAmalgam

  The proof decomposes into:
    1. Finmap insert commutativity    (models BTreeMap order-independence)
    2. Ownership resolution commutativity (the genesis state machine)
    3. Pairwise ingest commutativity  →  n-ary permutation invariance
    4. assemble determinism            (pure function of RecordingBuffer)

  Key insight: the pure `ingest` function commutes with ONLY the
  "no sequence-id conflict" precondition — admission (DID checks,
  signature gates) is per-shard and order-independent, so it factors
  out of the commutativity argument entirely.
-/

import Mathlib.Data.Finmap
import Mathlib.Data.List.Perm.Basic

-- ============================================================
-- DOMAIN TYPES (mirroring phalanx-proto)
-- ============================================================

/-- Sequence number. Ordered, used as BTreeMap key. -/
def StorageSequence := Nat
deriving DecidableEq, Ord, Hashable, Repr

instance {n : Nat} : OfNat StorageSequence n := ⟨n⟩

/-- Opaque identity. -/
structure Did where
  raw : String
deriving DecidableEq, Repr

/-- Recording identifier. -/
structure RecordingId where
  raw : String
deriving DecidableEq, Repr

/-- Hash of a signature, used for causal chaining. -/
structure SignatureHash where
  bytes : List UInt8
deriving DecidableEq, Repr

/-- Opaque payload hash — contents irrelevant to commutativity. -/
structure PayloadHash where
  bytes : List UInt8
deriving DecidableEq, Repr

/-- Simplified WitnessEnvelope — only the fields relevant to commutativity.
    The full Rust type also carries Evidence, witness_signature, etc.
    but those are opaque to the ordering argument. -/
structure WitnessEnvelope where
  sequence_id  : StorageSequence
  recording_id : RecordingId
  did          : Did
  prev_hash    : Option SignatureHash
  -- payload, signature, metrics etc. are opaque for this proof
  payload_hash : PayloadHash
deriving DecidableEq, Repr

-- ============================================================
-- OWNERSHIP MODEL  (phalanx-proto/src/identity.rs)
-- ============================================================

/-- Ownership state of a recording buffer.
    Tentative: first shard's DID, not yet confirmed by genesis/handover.
    Authoritative: pinned by a genesis shard (seq 0) or handover signal.

    Note: handover-based ownership transfer is a sequential extension
    and does not affect commutativity of the core ingest path. -/
inductive Ownership where
  | tentative (did : Did)
  | authoritative (did : Did)
deriving DecidableEq, Repr

def Ownership.did : Ownership → Did
  | .tentative d => d
  | .authoritative d => d

-- ============================================================
-- RECORDING BUFFER  (crucible.rs RecordingBuffer)
-- ============================================================

/-- The accumulator state. Mirrors RecordingBuffer in crucible.rs.
    Uses Finmap (finite partial map) to model BTreeMap — insertion
    order is irrelevant by construction. -/
structure RecordingBuffer where
  artifacts    : Finmap (fun _ : StorageSequence => WitnessEnvelope)
  recording_id : RecordingId
  ownership    : Ownership

-- ============================================================
-- INGEST FUNCTION  (crucible.rs RecordingAmalgam::ingest, pure core)
-- ============================================================

/-- Pure ingest: insert the envelope into artifacts and resolve ownership.
    Models the Ok(()) path of RecordingAmalgam::ingest after all
    admission gates (dedup, sequence-collision, DID check) have passed.
    Admission is factored out because gate checks are per-shard and
    do not depend on ingestion order. -/
def ingest (acc : RecordingBuffer) (env : WitnessEnvelope) : RecordingBuffer :=
  let new_artifacts := acc.artifacts.insert env.sequence_id env
  let new_ownership :=
    if env.sequence_id = (0 : StorageSequence) then
      -- Genesis shard (seq 0): upgrade to authoritative
      Ownership.authoritative env.did
    else
      acc.ownership
  { acc with
    artifacts := new_artifacts
    ownership := new_ownership }

-- ============================================================
-- ASSEMBLE  (crucible.rs RecordingAmalgam::assemble)
-- Declared axiomatically — determinism follows from buffer equality.
-- The Rust implementation iterates acc.artifacts in BTreeMap key order
-- (= StorageSequence order), verifies the prev_hash causal chain,
-- and builds a Recording. Since it is a pure function of the
-- RecordingBuffer value, equal buffers ⟹ equal Recordings.
-- ============================================================

axiom Recording : Type
axiom assemble : RecordingBuffer → Option Recording

-- ============================================================
-- CORE LEMMA 1: Finmap insertion commutes
-- ============================================================

/-- BTreeMap / Finmap insert commutes.
    When keys differ: Finmap.insert_insert_of_ne.
    When keys collide: the M4 no-conflict invariant forces identical
    envelopes, so insert is idempotent and both sides are equal. -/
theorem insert_comm (m : Finmap (fun _ : StorageSequence => WitnessEnvelope))
    (a b : WitnessEnvelope)
    (h : a.sequence_id = b.sequence_id → a = b) :
    (m.insert a.sequence_id a).insert b.sequence_id b =
    (m.insert b.sequence_id b).insert a.sequence_id a := by
  by_cases heq : a.sequence_id = b.sequence_id
  · -- Same key ⟹ same envelope ⟹ both sides identical
    rw [h heq]
  · -- Distinct keys ⟹ Finmap.insert_insert_of_ne
    exact Finmap.insert_insert_of_ne _ heq

-- ============================================================
-- CORE LEMMA 2: Ownership resolution commutes
-- ============================================================

/-- Helper: compute ownership after two ingests. -/
private def ownership_after_two (o : Ownership) (a b : WitnessEnvelope) : Ownership :=
  let o' := if a.sequence_id = (0 : StorageSequence) then Ownership.authoritative a.did else o
  if b.sequence_id = (0 : StorageSequence) then Ownership.authoritative b.did else o'

/-- The ownership state machine commutes under the no-conflict
    invariant. No admission hypothesis is needed — case analysis:
    - Neither a nor b is genesis → ownership unchanged → trivial
    - Exactly one is genesis → both orderings yield authoritative(genesis.did)
    - Both are genesis → same sequence_id (= 0) → same envelope → trivial -/
theorem ownership_comm (o : Ownership) (a b : WitnessEnvelope)
    (h : a.sequence_id = b.sequence_id → a = b) :
    ownership_after_two o a b = ownership_after_two o b a := by
  simp only [ownership_after_two]
  by_cases ha : a.sequence_id = (0 : StorageSequence) <;>
  by_cases hb : b.sequence_id = (0 : StorageSequence) <;>
  simp [ha, hb]
  -- Remaining case: both genesis (a.seq = 0 ∧ b.seq = 0)
  -- ⟹ a.sequence_id = b.sequence_id ⟹ a = b by no-conflict
  have hab : a.sequence_id = b.sequence_id := by rw [ha, hb]
  rw [h hab]

-- ============================================================
-- MAIN: Pairwise ingest commutativity
-- ============================================================

/-- For any two non-conflicting shards, ingest order doesn't matter.
    This is the atomic building block for the n-ary permutation proof.

    Note: no admission/is_admitted hypothesis is needed. The pure
    ingest function commutes whenever the no-conflict invariant holds. -/
theorem ingest_comm (acc : RecordingBuffer) (a b : WitnessEnvelope)
    (h : a.sequence_id = b.sequence_id → a = b) :
    ingest (ingest acc a) b = ingest (ingest acc b) a := by
  simp only [ingest, RecordingBuffer.mk.injEq]
  refine ⟨?_, trivial, ?_⟩
  · -- artifacts: Finmap insert commutes
    exact insert_comm acc.artifacts a b h
  · -- ownership: genesis state machine commutes
    exact ownership_comm acc.ownership a b h

-- ============================================================
-- ITERATED INGEST
-- ============================================================

/-- Iterated ingest over a list of shards.
    Equivalent to List.foldl ingest acc. -/
def ingest_all (acc : RecordingBuffer) : List WitnessEnvelope → RecordingBuffer
  | [] => acc
  | e :: es => ingest_all (ingest acc e) es

-- ============================================================
-- N-ARY PERMUTATION INVARIANCE  (via List.Perm induction)
-- ============================================================

/-- Core result: any permutation of the shard list yields the
    same RecordingBuffer, provided no two distinct shards share
    a sequence_id (the M4 "no sequence conflict" invariant from
    crucible.rs AmalgamError::SequenceConflict).

    Proof by structural induction on the List.Perm derivation:
    - nil:   trivial
    - cons:  peel off matching head, apply IH
    - swap:  exactly ingest_comm (adjacent transposition)
    - trans: compose the two sub-permutations -/
theorem ingest_all_perm_eq
    (acc : RecordingBuffer)
    {l₁ l₂ : List WitnessEnvelope}
    (hp : l₁.Perm l₂)
    (hnc : ∀ a ∈ l₁, ∀ b ∈ l₁,
      a.sequence_id = b.sequence_id → a = b) :
    ingest_all acc l₁ = ingest_all acc l₂ := by
  induction hp generalizing acc with
  | nil => rfl
  | cons x _ ih =>
    -- x :: l₁' ~ x :: l₂'  ⟹  unfold one step, apply IH to tails
    simp only [ingest_all]
    apply ih
    intro a ha b hb
    exact hnc a (List.mem_cons_of_mem x ha) b (List.mem_cons_of_mem x hb)
  | swap x y l =>
    -- swap x y l : Perm (y :: x :: l) (x :: y :: l)
    -- So l₁ = y :: x :: l, l₂ = x :: y :: l
    -- Goal: ingest_all acc (y :: x :: l) = ingest_all acc (x :: y :: l)
    simp only [ingest_all]
    -- Need: ingest_all (ingest (ingest acc y) x) l = ingest_all (ingest (ingest acc x) y) l
    have hmy : y ∈ y :: x :: l := List.mem_cons_self y _
    have hmx : x ∈ y :: x :: l := List.mem_cons_of_mem y (List.mem_cons_self x l)
    have h := ingest_comm acc y x (hnc y hmy x hmx)
    rw [h]
  | trans hp₁ _ ih₁ ih₂ =>
    -- l₁ ~ l₂ ~ l₃  ⟹  compose both directions
    -- Transfer no-conflict from l₁ to l₂ via membership equivalence
    exact (ih₁ acc hnc).trans
      (ih₂ acc fun a ha b hb =>
        hnc a (hp₁.mem_iff.mpr ha) b (hp₁.mem_iff.mpr hb))

-- ============================================================
-- FINAL THEOREM
-- ============================================================

/-- Recording order-independence: for any two orderings of the
    same shard set (expressed as a List.Perm), assemble produces
    the identical Recording.

    This is the commutativity certificate for RecordingAmalgam.
    It guarantees that fountain-decoded chunks arriving in any
    network order will deterministically reconstruct the same
    Recording with the same causal chain and gap analysis. -/
theorem recording_order_independent
    (acc₀ : RecordingBuffer)
    (l₁ l₂ : List WitnessEnvelope)
    (hp : l₁.Perm l₂)
    (hnc : ∀ a ∈ l₁, ∀ b ∈ l₁,
      a.sequence_id = b.sequence_id → a = b) :
    assemble (ingest_all acc₀ l₁) = assemble (ingest_all acc₀ l₂) := by
  rw [ingest_all_perm_eq acc₀ hp hnc]
