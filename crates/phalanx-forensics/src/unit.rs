//! The `ForensicUnit` typestate — an in-process verification construct.
//!
//! `ForensicUnit<T, S>` tags a payload with a validation state `S`, so
//! unverified data and verified/sealed evidence are distinct types the
//! compiler keeps apart. The states are produced and consumed entirely by
//! this crate's gates; `ForensicUnit` has no wire representation.
//!
//! Forgery resistance is structural: the fields are private, the type does
//! not implement `Serialize`/`Deserialize`, `ValidationState` is sealed, and
//! the unchecked constructors are `pub(crate)` — only `phalanx-forensics` can
//! mint a `Verified` or `Sealed` unit, and only by routing through a gate
//! (`PromotionGate`, `EgressGovernor`).
//!
//! # Structural invariants (CI-enforced)
//!
//! Each doc-test below is compiled as a separate external crate and must
//! **fail** to compile. They are the executable proof that the typestate
//! cannot be forged from outside `phalanx-forensics`; if any one starts
//! compiling, an evidence-forgery path has reopened and this test turns red.
//!
//! `Verified` cannot be minted without a gate — `new_verified_unchecked` is
//! `pub(crate)`:
//!
//! ```compile_fail
//! use phalanx_forensics::unit::{ForensicUnit, Verified};
//! let _forge = ForensicUnit::<u8, Verified>::new_verified_unchecked;
//! ```
//!
//! `Verified` cannot be sealed without `EgressGovernor::authorize` —
//! `seal_unchecked` is `pub(crate)`:
//!
//! ```compile_fail
//! use phalanx_forensics::unit::{ForensicUnit, Sealed, Verified};
//! let _forge: fn(ForensicUnit<u8, Verified>) -> ForensicUnit<u8, Sealed> =
//!     ForensicUnit::<u8, Verified>::seal_unchecked;
//! ```
//!
//! No state can be reached by a struct literal — the fields are private:
//!
//! ```compile_fail
//! use phalanx_forensics::unit::{ForensicUnit, Verified};
//! use std::marker::PhantomData;
//! let _forge = ForensicUnit::<u8, Verified> { data: 7u8, _state: PhantomData };
//! ```
//!
//! The state set is closed — `ValidationState` is sealed, so no outside crate
//! can add a fourth, privileged state:
//!
//! ```compile_fail
//! struct Forged;
//! impl phalanx_forensics::unit::ValidationState for Forged {}
//! ```
//!
//! A unit cannot be conjured from attacker-controlled bytes — `ForensicUnit`
//! has no `Deserialize` impl:
//!
//! ```compile_fail
//! use phalanx_forensics::unit::{ForensicUnit, Sealed};
//! let bytes: &[u8] = &[];
//! let _forge = postcard::from_bytes::<ForensicUnit<u8, Sealed>>(bytes);
//! ```

use std::marker::PhantomData;

mod sealed {
    /// Private supertrait of [`super::ValidationState`]. Because it cannot be
    /// named outside this crate, the set of validation states is closed.
    pub trait Sealed {}
}

/// Marker trait for the `ForensicUnit` validation states. Sealed — no crate
/// can introduce a new state.
pub trait ValidationState: sealed::Sealed {}

/// Data straight off the wire — not yet verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unverified;

/// Evidence whose Ed25519 witness signature has been verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified;

/// Evidence authorized for egress (encryption applied).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sealed;

impl sealed::Sealed for Unverified {}
impl sealed::Sealed for Verified {}
impl sealed::Sealed for Sealed {}

impl ValidationState for Unverified {}
impl ValidationState for Verified {}
impl ValidationState for Sealed {}

/// A payload `T` tagged with a validation state `S`.
///
/// Has no wire form — evidence crosses the network as a bare `WitnessEnvelope`,
/// and the receiver must re-wrap it [`Unverified`] and run a gate.
#[derive(Debug, Clone)]
pub struct ForensicUnit<T, S: ValidationState> {
    data: T,
    _state: PhantomData<S>,
}

impl<T> ForensicUnit<T, Unverified> {
    /// Wrap raw, unverified data taken off the wire.
    pub fn new(data: T) -> Self {
        Self {
            data,
            _state: PhantomData,
        }
    }
}

impl<T> ForensicUnit<T, Verified> {
    /// Mint a `Verified` unit *without* verification.
    ///
    /// DANGER: skips every gate. `pub(crate)` so only `phalanx-forensics` can
    /// call it — the legitimate callers are the promotion gates and
    /// `EgressGovernor::authorize` (which re-wraps after encrypting the
    /// payload). Code outside this crate reaches `Verified` only through the
    /// `pub` gates, which perform real verification.
    pub(crate) fn new_verified_unchecked(data: T) -> Self {
        Self {
            data,
            _state: PhantomData,
        }
    }

    /// Promote `Verified` to `Sealed` *without* egress-policy checks.
    ///
    /// DANGER: skips the egress policy. `pub(crate)` so the only caller is
    /// `EgressGovernor::authorize`.
    pub(crate) fn seal_unchecked(self) -> ForensicUnit<T, Sealed> {
        ForensicUnit {
            data: self.data,
            _state: PhantomData,
        }
    }
}

impl<T, S: ValidationState> ForensicUnit<T, S> {
    /// Borrow the wrapped payload. Reading never changes the validation state.
    pub fn data(&self) -> &T {
        &self.data
    }

    /// Consume the wrapper and return the raw payload.
    pub fn unpack(self) -> T {
        self.data
    }
}
