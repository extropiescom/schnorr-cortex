// -*- mode: rust; -*-
//
// This file is part of schnorr-cortex.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>
// - Jeffrey Burdges <jeff@web3.foundation>
// - Chester Lee <chester@extropies.com>

//! Schnorr signature variants using Ristretto point compression.
//!
//! # Example
//!


#![no_std]
#![warn(future_incompatible)]
#![warn(rust_2018_compatibility)]
#![warn(rust_2018_idioms)]
// embedded features
#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![cfg(target_arch = "arm")]


extern crate curve25519_dalek;
extern crate merlin;
extern crate subtle;
extern crate failure;
extern crate ed25519_dalek;
extern crate sha2;

extern crate rand_core;

//embedded crates
extern crate alloc;
extern crate alloc_cortex_m;
extern crate cortex_m_rt as rt;



#[macro_use]
pub mod points;
pub mod scalars;
pub mod keys;
pub mod context;
pub mod sign;
pub mod derive;
pub mod errors;
pub mod embedded;
pub mod onchip;


pub use crate::keys::*; // {MiniSecretKey,SecretKey,PublicKey,Keypair}; + *_LENGTH
pub use crate::context::{signing_context}; // SigningContext,SigningTranscript
pub use crate::sign::{Signature,SIGNATURE_LENGTH};
pub use crate::errors::{SignatureError,SignatureResult};


use alloc_cortex_m::CortexMHeap;
#[global_allocator]
static ALLOCATOR: CortexMHeap = CortexMHeap::empty();









