//! Configuration types and constants for the stability analysis module.
//!
//! I had to pull out the rat glue for this one. This is 100% 'roach scholar' energy. Thank you Dr. Calvetti.
//!
//! This is what happens when a numerical analyst who doesn't know any better decides to
//! design a distributed mesh.
//!
//! What you see here is a result of frustration. I am not a good programmer in the classical
//! sense- or any sense really. I am a compulsive problem solver with a deep disdain for friction;
//! not the physical concept of friction- that's supremely useful. I'm talking about design friction.
//!
//! The first pass at Phalanx started as many hobby projects do- a monolithic ball of mud. This was fine
//! when the project was 5-10 files and didn't do much beyond send a jpeg still over gossipsub. As the project
//! grew, so did the parameter count. Now, because I'm a bad programmer, who is always trying to become a
//! better programmer, I was forcing myself to use test driven design because that is what the 'best'
//! (for my particular definition of best) programmers do. And because I'm a bad programmer, who had a
//! shit architecture to start, my tests would break every time I added a new feature. I found myself
//! changing parameters to make one test work only to break another. It. fucking. sucked.
//!
//! There had to be a better way, so I set out to build one. My first idea was to derive a fundamental
//! set of constants that every parameter in the code base would depend on. I forget what the initial ones
//! were (they're in the git history so I guess I don't have to remember.), but I do remember network round trip
//! time being the big one. I implemented it and it worked! For a while. Testing revealed that the mesh was still
//! brittle which, in hindsight, makes so much sense because I didn't actually solve the real problem. I just
//! reduced the number of parameters I was arbitrarily assigning values to. There had to be a better way.
//!
//! The insight came to me in the small hours of the morning while I was watching my parents very fancy
//! coffee machine make my coffee. What if I just didn't use constants at all? What if I tried
//! modeling this whole thing using a system of differential equations. So that's what I tried. And before
//! my pencil hit the paper, I realized that that idea too would fail. Network signals are inherently
//! non-differentiable; and even if they were, numerical differentiation is inherently unstable. It
//! could never work. It would simply be a 'clever' trick that wasn't all that clever.
//!
//! And then I remembered my training- I could hear Dr. Somersalo (not unlike Yoda whispering to Luke,
//! except with less magic) "Use the integral equations, Joe." And as this is all coming to me while
//! staring at this coffee machine, I'm watching this machine force hot water through a brick of coffee
//! grounds until the pressure accumulates to a point where it must pass through.
//!
//! Pressure. The whole system could be modeled by a system of coupled integral equations. Integral
//! equations (for the most part) are inherently stable. I could model the pressure using Volterra
//! integral equations of the second kind. So I did- and this time it really worked.
//!
//! I still had one last problem to solve. How would I know if it always worked? You see,
//! I've never designed a distributed system before. How would I test this idea at scale?
//! That would require programming an elaborate simulation harness, and what would that prove?
//! That the system would work as intended simply because I the simulation long enough using
//! similarly contrived parameters? No. Unacceptable. Once again, there had to be a better way.
//!
//! This time, it was Dr. Calvetti that whispered to me. "You're a roach scholar, Joe. This is the
//! time for that rat glue. You glue yourself to the chair until the work is done." So I did- not
//! literally, I'm not a psychopath. My plan of attack went something like this:
//! 1. Show that a node is locally stable by looking at my freshly minted system Jacobian
//! 2. Show that a failure in one node couldn't cascade into another.
//! 3. Show that a node could survive under duress as t -> \infty
//!
//! What you see here is that plan in action. And oh, by they way, if you happen to model your
//! distributed system this way you get Byzantine actor detection for roughly 100 FLOPS of
//! additional work. You just have to look at the spectral gap between what the nodes claims
//! they are doing and what they are actually doing. All nodes must live in the manifold
//! defined by the integral equations that govern this system. A dishonest node has nowhere to
//! hide- it cannot escape the math.

use crate::vitals::HomeostaticConfig;

// Index mapping for the 8 integrals.
pub const S: usize = 0; // System / metabolic pressure
pub const D: usize = 1; // I/O digestion pressure
pub const E: usize = 2; // Entry / Sybil pressure
pub const L: usize = 3; // Latency (network/scheduling age)
pub const M: usize = 4; // Memory / buffer pressure
pub const W: usize = 5; // WAL / storage pressure
pub const B: usize = 6; // Bandwidth pressure
pub const C: usize = 7; // Connection pressure

pub const DIM: usize = 8;

/// Labels for each integral index.
pub const INTEGRAL_NAMES: [&str; DIM] = ["s", "d", "e", "l", "m", "w", "b", "c"];

// =====================================================================
// CONFIGURATION TYPES
// =====================================================================

/// Base (unthrottled) impulse rates for each integral under a given traffic
/// scenario.  Units are impulse/second — the average rate at which events
/// would feed each integral if no scaler or gate were active.
#[derive(Debug, Clone)]
pub struct BaseImpulseRates {
    pub u_s: f64, // metabolic: seconds of CPU per second (fractional utilization)
    pub u_d: f64, // I/O: seconds of fetch latency per second
    pub u_e: f64, // entry: shard arrivals per second
    pub u_l: f64, // latency: average shard-age seconds contributed per second
    pub u_m: f64, // memory: MiB accumulated per second
    pub u_w: f64, // storage: utilization-ratio increments per second
    pub u_b: f64, // bandwidth: MiB ingress per second
    pub u_c: f64, // connection: ratio increments per second
}

impl BaseImpulseRates {
    /// Light traffic — a mostly-idle node.
    pub fn light() -> Self {
        Self {
            u_s: 0.5,
            u_d: 0.2,
            u_e: 2.0,
            u_l: 0.1,
            u_m: 5.0,
            u_w: 0.01,
            u_b: 2.0,
            u_c: 0.05,
        }
    }

    /// Moderate traffic — typical operating conditions.
    pub fn moderate() -> Self {
        Self {
            u_s: 2.0,
            u_d: 1.0,
            u_e: 10.0,
            u_l: 0.5,
            u_m: 50.0,
            u_w: 0.05,
            u_b: 10.0,
            u_c: 0.2,
        }
    }

    /// Heavy traffic — sustained high load or flood.
    pub fn heavy() -> Self {
        Self {
            u_s: 5.0,
            u_d: 3.0,
            u_e: 50.0,
            u_l: 2.0,
            u_m: 200.0,
            u_w: 0.15,
            u_b: 40.0,
            u_c: 0.5,
        }
    }
}

/// Operating point at which the system is linearized.
/// Values represent the current integral magnitudes.
#[derive(Debug, Clone)]
pub struct OperatingPoint {
    pub vals: [f64; DIM],
}

impl OperatingPoint {
    /// System at rest — all integrals near zero.
    pub fn idle() -> Self {
        Self { vals: [0.0; DIM] }
    }

    /// Half-critical — each integral at 50% of its critical threshold (or a
    /// representative mid-range value for integrals without a threshold).
    pub fn half_critical(cfg: &HomeostaticConfig) -> Self {
        Self {
            vals: [
                cfg.s_crit * 0.5, // s
                cfg.d_crit * 0.5, // d
                5.0,              // e (representative mid-range)
                2.0,              // l (seconds of accumulated latency)
                cfg.m_crit * 0.5, // m
                cfg.w_crit * 0.5, // w
                cfg.b_crit * 0.5, // b
                cfg.c_crit * 0.5, // c
            ],
        }
    }

    /// Near-critical — integrals at 80% of threshold.
    pub fn near_critical(cfg: &HomeostaticConfig) -> Self {
        Self {
            vals: [
                cfg.s_crit * 0.8,
                cfg.d_crit * 0.8,
                15.0,
                5.0,
                cfg.m_crit * 0.8,
                cfg.w_crit * 0.8,
                cfg.b_crit * 0.8,
                cfg.c_crit * 0.8,
            ],
        }
    }
}
