// -*- mode: rust; -*-
//
// This file is part of schnorrkel.
// Copyright (c) 2017-2019 Isis Lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - Isis Agora Lovecruft <isis@patternsinthevoid.net>
// - Jeffrey Burdges <jeff@web3.foundation>

//! Schnorr signature variants using Ristretto point compression.
//!
//! # Example
//!
//! Creating a signature on a message is simple.
//!
//! First, we need to generate a `Keypair`, which includes both public and
//! secret halves of an asymmetric key.  To do so, we need a cryptographically
//! secure pseudorandom number generator (CSPRNG), and a hash function which
//! has 512 bits of output.  For this example, we'll use the operating
//! system's builtin PRNG and SHA-512 to generate a keypair:
//!
//! ```
//! extern crate rand;
//! extern crate schnorrkel;
//!
//! # #[cfg(all(feature = "std"))]
//! # fn main() {
//! use rand::{Rng, rngs::OsRng};
//! use schnorrkel::{Keypair,Signature};
//!
//! let mut csprng: OsRng = OsRng::new().unwrap();
//! let keypair: Keypair = Keypair::generate(&mut csprng);
//! # }
//! #
//! # #[cfg(any(not(feature = "std")))]
//! # fn main() { }
//! ```
//!
//! We can now use this `keypair` to sign a message:
//!
//! ```
//! # extern crate rand;
//! # extern crate rand_chacha;
//! # extern crate schnorrkel;
//! # fn main() {
//! # use rand::{SeedableRng}; // Rng
//! # use rand_chacha::ChaChaRng;
//! # use schnorrkel::{Keypair,Signature,signing_context};
//! # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
//! # let keypair: Keypair = Keypair::generate(&mut csprng);
//! let context = signing_context(b"this signature does this thing");
//! let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
//! let signature: Signature = keypair.sign(context.bytes(message));
//! # }
//! ```
//!
//! As well as to verify that this is, indeed, a valid signature on
//! that `message`:
//!
//! ```
//! # extern crate rand;
//! # extern crate rand_chacha;
//! # extern crate schnorrkel;
//! # fn main() {
//! # use rand::{SeedableRng}; // Rng
//! # use rand_chacha::ChaChaRng;
//! # use schnorrkel::{Keypair,Signature,signing_context};
//! # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
//! # let keypair: Keypair = Keypair::generate(&mut csprng);
//! # let context = signing_context(b"this signature does this thing");
//! # let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
//! # let signature: Signature = keypair.sign(context.bytes(message));
//! assert!(keypair.verify(context.bytes(message), &signature).is_ok());
//! # }
//! ```
//!
//! Anyone else, given the `public` half of the `keypair` can also easily
//! verify this signature:
//!
//! ```
//! # extern crate rand;
//! # extern crate rand_chacha;
//! # extern crate schnorrkel;
//! # fn main() {
//! # use rand::{SeedableRng}; // Rng
//! # use rand_chacha::ChaChaRng;
//! # use schnorrkel::{Keypair,Signature,signing_context};
//! use schnorrkel::PublicKey;
//! # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
//! # let keypair: Keypair = Keypair::generate(&mut csprng);
//! # let context = signing_context(b"this signature does this thing");
//! # let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
//! # let signature: Signature = keypair.sign(context.bytes(message));
//! let public_key: PublicKey = keypair.public;
//! assert!(public_key.verify(context.bytes(message), &signature).is_ok());
//! # }
//! ```
//!
//! ## Serialisation
//!
//! `PublicKey`s, `MiniSecretKey`s, `Keypair`s, and `Signature`s can be serialised
//! into byte-arrays by calling `.to_bytes()`.  It's perfectly acceptible and
//! safe to transfer and/or store those bytes.  (Of course, never transfer your
//! secret key to anyone else, since they will only need the public key to
//! verify your signatures!)
//!
//! ```
//! # extern crate rand;
//! # extern crate rand_chacha;
//! # extern crate schnorrkel;
//! # fn main() {
//! # use rand::{Rng, SeedableRng};
//! # use rand_chacha::ChaChaRng;
//! # use schnorrkel::{Keypair, Signature, PublicKey, signing_context};
//! use schnorrkel::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, KEYPAIR_LENGTH, SIGNATURE_LENGTH};
//! # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
//! # let keypair: Keypair = Keypair::generate(&mut csprng);
//! # let context = signing_context(b"this signature does this thing");
//! # let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
//! # let signature: Signature = keypair.sign(context.bytes(message));
//! # let public_key: PublicKey = keypair.public;
//!
//! let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = public_key.to_bytes();
//! let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = keypair.secret.to_bytes();
//! let keypair_bytes:    [u8; KEYPAIR_LENGTH]    = keypair.to_bytes();
//! let signature_bytes:  [u8; SIGNATURE_LENGTH]  = signature.to_bytes();
//! # }
//! ```
//!
//! And similarly, decoded from bytes with `::from_bytes()`:
//!
//! ```
//! # extern crate rand;
//! # extern crate rand_chacha;
//! # extern crate schnorrkel;
//! # use rand::{Rng, SeedableRng};
//! # use rand_chacha::ChaChaRng;
//! # use schnorrkel::{SecretKey, Keypair, Signature, PublicKey, SignatureError, signing_context};
//! # use schnorrkel::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, KEYPAIR_LENGTH, SIGNATURE_LENGTH};
//! # fn do_test() -> Result<(SecretKey, PublicKey, Keypair, Signature), SignatureError> {
//! # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
//! # let keypair_orig: Keypair = Keypair::generate(&mut csprng);
//! # let context = signing_context(b"this signature does this thing");
//! # let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
//! # let signature_orig: Signature = keypair_orig.sign(context.bytes(message));
//! # let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = keypair_orig.public.to_bytes();
//! # let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = keypair_orig.secret.to_bytes();
//! # let keypair_bytes:    [u8; KEYPAIR_LENGTH]    = keypair_orig.to_bytes();
//! # let signature_bytes:  [u8; SIGNATURE_LENGTH]  = signature_orig.to_bytes();
//! #
//! let public_key: PublicKey = PublicKey::from_bytes(&public_key_bytes)?;
//! let secret_key: SecretKey = SecretKey::from_bytes(&secret_key_bytes)?;
//! let keypair:    Keypair   = Keypair::from_bytes(&keypair_bytes)?;
//! let signature:  Signature = Signature::from_bytes(&signature_bytes)?;
//! #
//! # Ok((secret_key, public_key, keypair, signature))
//! # }
//! # fn main() {
//! #     do_test();
//! # }
//! ```
//!
//! ### Using Serde
//!
//! If you prefer the bytes to be wrapped in another serialisation format, all
//! types additionally come with built-in [serde](https://serde.rs) support by
//! building `schnorrkell` via:
//!
//! ```bash
//! $ cargo build --features="serde"
//! ```
//!
//! They can be then serialised into any of the wire formats which serde supports.
//! For example, using [bincode](https://github.com/TyOverby/bincode):
//!
//! ```
//! # extern crate rand;
//! # extern crate rand_chacha;
//! # extern crate schnorrkel;
//! # #[cfg(feature = "serde")]
//! extern crate serde;
//! # #[cfg(feature = "serde")]
//! extern crate bincode;
//!
//! # #[cfg(feature = "serde")]
//! # fn main() {
//! # use rand::{Rng, SeedableRng};
//! # use rand_chacha::ChaChaRng;
//! # use schnorrkel::{Keypair, Signature, PublicKey, signing_context};
//! use bincode::{serialize, Infinite};
//! # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
//! # let keypair: Keypair = Keypair::generate(&mut csprng);
//! # let context = signing_context(b"this signature does this thing");
//! # let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
//! # let signature: Signature = keypair.sign(context.bytes(message));
//! # let public_key: PublicKey = keypair.public;
//! # let verified: bool = public_key.verify(context.bytes(message), &signature);
//!
//! let encoded_public_key: Vec<u8> = serialize(&public_key, Infinite).unwrap();
//! let encoded_signature: Vec<u8> = serialize(&signature, Infinite).unwrap();
//! # }
//! # #[cfg(not(feature = "serde"))]
//! # fn main() {}
//! ```
//!
//! After sending the `encoded_public_key` and `encoded_signature`, the
//! recipient may deserialise them and verify:
//!
//! ```
//! # extern crate rand;
//! # extern crate rand_chacha;
//! # extern crate schnorrkel;
//! # #[cfg(feature = "serde")]
//! # extern crate serde;
//! # #[cfg(feature = "serde")]
//! # extern crate bincode;
//! #
//! # #[cfg(feature = "serde")]
//! # fn main() {
//! # use rand::{Rng, SeedableRng};
//! # use rand_chacha::ChaChaRng;
//! # use schnorrkel::{Keypair, Signature, PublicKey, signing_context};
//! # use bincode::{serialize, Infinite};
//! use bincode::{deserialize};
//!
//! # let mut csprng: ChaChaRng = ChaChaRng::from_seed([0u8; 32]);
//! # let keypair: Keypair = Keypair::generate(&mut csprng);
//! let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
//! # let context = signing_context(b"this signature does this thing");
//! # let signature: Signature = keypair.sign(context.bytes(message));
//! # let public_key: PublicKey = keypair.public;
//! # let verified: bool = public_key.verify(context.bytes(message), &signature);
//! # let encoded_public_key: Vec<u8> = serialize(&public_key, Infinite).unwrap();
//! # let encoded_signature: Vec<u8> = serialize(&signature, Infinite).unwrap();
//! let decoded_public_key: PublicKey = deserialize(&encoded_public_key).unwrap();
//! let decoded_signature: Signature = deserialize(&encoded_signature).unwrap();
//!
//! # assert_eq!(public_key, decoded_public_key);
//! # assert_eq!(signature, decoded_signature);
//! #
//! let verified: bool = decoded_public_key.verify(context.bytes(message), &decoded_signature).is_ok();
//!
//! assert!(verified);
//! # }
//! # #[cfg(not(feature = "serde"))]
//! # fn main() {}
//! ```

#![no_std]
#![feature(alloc)]
#![feature(global_allocator)]
#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![warn(future_incompatible)]
#![warn(rust_2018_compatibility)]
#![warn(rust_2018_idioms)]
#![cfg(target_arch = "arm")]
//#![deny(missing_docs)] // refuse to compile if documentation is missing

extern crate alloc;

extern crate alloc_cortex_m;
//extern crate cortex_m_semihosting;

#[macro_use]
//extern crate cortex_m_rt as rt; // v0.5.x

extern crate curve25519_dalek;
extern crate merlin;
extern crate clear_on_drop;
extern crate subtle;
extern crate rand;
extern crate rand_chacha;
extern crate failure;
extern crate ed25519_dalek;
#[cfg(test)]
extern crate sha3;
extern crate sha2;
#[cfg(feature = "serde")]
extern crate serde;
#[cfg(all(test, feature = "serde"))]
extern crate bincode;

extern crate cortex_m_rt as rt;

#[macro_use]
mod serdey;
pub mod points;
mod scalars;
pub mod keys;
pub mod context;
pub mod sign;
pub mod vrf;
pub mod derive;
pub mod cert;
pub mod errors;
#[cfg(any(feature = "alloc", feature = "std"))]
pub mod musig;
mod wrapper;
pub use crate::keys::*; // {MiniSecretKey,SecretKey,PublicKey,Keypair}; + *_LENGTH
pub use crate::context::{signing_context}; // SigningContext,SigningTranscript
pub use crate::sign::{Signature,SIGNATURE_LENGTH};
pub use crate::errors::{SignatureError,SignatureResult};
#[cfg(any(feature = "alloc", feature = "std"))]
pub use crate::sign::{verify_batch};

use core::default::Default;
use core::panic::PanicInfo;
use wrapper::*;
use core::slice;
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc_cortex_m::CortexMHeap;
use rand::{SeedableRng}; // Rng
use rand_chacha::ChaChaRng;

#[global_allocator]
static ALLOCATOR: CortexMHeap = CortexMHeap::empty();


const PUB_KEY_LEN:u32 = 32;
const PRI_KEY_LEN:u32 = 64;
const STATUS_OK:u32 = 0;


#[repr(C)]
pub struct sr_data{
	status:u32,
    data:[u8;96],
    len: u32
}
#[no_mangle]
pub unsafe extern "C" fn test_box(message:*const u8)->*mut u8{
	let start:usize = rt::heap_start() as usize;
    let size:usize = 1024; // in bytes
	unsafe { ALLOCATOR.init(start, size) }
	let rseed: &[u8] = unsafe { slice::from_raw_parts(message, 96)};
	let mut data:[u8;96] = [0;96];
	let status:u32 = STATUS_OK;
	let len : u32 = PUB_KEY_LEN+PRI_KEY_LEN;
	let mut i =0;
	while i<96 {
		data[i] = rseed[i];
		i = i+1;
	}

	let sr_data = sr_data { data, len, status};
	let b = Box::new(sr_data);
	return Box::into_raw(b) as *mut u8;
}

#[no_mangle]
pub unsafe extern "C" fn test_sign_verify()->u8
{
	const SIGNING_CTX: &'static [u8] = b"good";
	let context = signing_context(SIGNING_CTX);
	let keypair: Keypair;
	let keypair_bytes: [u8;96] = [74,83,195,251,188,89,151,14,229,248,90,248,19,135,93,255,193,58,144,74,46,83,174,126,101,250,13,234,110,98,201,1,159,7,231,190,85,81,56,122,152,186,151,124,115,45,8,13,203,15,41,160,72,227,101,105,18,198,83,62,50,238,122,237,156,102,163,57,200,52,79,146,47,195,32,108,181,218,232,20,165,148,192,23,125,211,35,92,37,77,156,64,154,101,184,8];
	let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
	keypair  = Keypair::from_bytes(&keypair_bytes[..]).unwrap();
	let signature: Signature = keypair.sign(context.bytes(message));
	 if keypair.verify(context.bytes(&message), &signature).is_ok()
    		{12}
	   else
	   		{13}
}

#[no_mangle]
pub unsafe extern "C" fn test_sign_ptr() -> *mut u8{
	 //legt start:usize = 0x2000700;
	  let start = rt::heap_start() as usize;
     let size:usize = 1024; // in bytes
	 unsafe { ALLOCATOR.init(start, size) }

	const SIGNING_CTX: &'static [u8] = b"good";
	let context = signing_context(SIGNING_CTX);
	let keypair: Keypair;
	let keypair_bytes: [u8;96] = [74,83,195,251,188,89,151,14,229,248,90,248,19,135,93,255,193,58,144,74,46,83,174,126,101,250,13,234,110,98,201,1,159,7,231,190,85,81,56,122,152,186,151,124,115,45,8,13,203,15,41,160,72,227,101,105,18,198,83,62,50,238,122,237,156,102,163,57,200,52,79,146,47,195,32,108,181,218,232,20,165,148,192,23,125,211,35,92,37,77,156,64,154,101,184,8];
	let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
	keypair  = Keypair::from_bytes(&keypair_bytes[..]).unwrap();
	let signature: Signature = keypair.sign(context.bytes(message));
	let signature_bytes = signature.to_bytes(); 
	//{signature_bytes[63]}

	let mut data:[u8;96] = [0;96];

	let mut i =0;
	while i<64 {
		data[i] = signature_bytes[i];
		i = i+1;
	}
	let b = Box::new(data);
	return Box::into_raw(b) as *mut u8;

}

#[no_mangle]
pub unsafe extern "C" fn test_sign() -> (Box<sr_data>){
	const SIGNING_CTX: &'static [u8] = b"good";
	let context = signing_context(SIGNING_CTX);
	let keypair: Keypair;
	let keypair_bytes: [u8;96] = [74,83,195,251,188,89,151,14,229,248,90,248,19,135,93,255,193,58,144,74,46,83,174,126,101,250,13,234,110,98,201,1,159,7,231,190,85,81,56,122,152,186,151,124,115,45,8,13,203,15,41,160,72,227,101,105,18,198,83,62,50,238,122,237,156,102,163,57,200,52,79,146,47,195,32,108,181,218,232,20,165,148,192,23,125,211,35,92,37,77,156,64,154,101,184,8];
	let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
	keypair  = Keypair::from_bytes(&keypair_bytes[..]).unwrap();
	let signature: Signature = keypair.sign(context.bytes(message));
	let signature_bytes = signature.to_bytes(); 

	let mut data:[u8;96] = [0;96];
	let status:u32 = STATUS_OK;
	let len : u32 = 64;

	let mut i =0;
	while i<64 {
		data[i] = signature_bytes[i];
		i = i+1;
	}
	let sr_data = sr_data { data: data,len:len, status:status};
	Box::new(sr_data)
}

#[no_mangle]
pub unsafe extern "C" fn add_rust(a:i8,b:i8) -> usize{
		const SIGNING_CTX: &'static [u8] = b"good";
		let context = signing_context(SIGNING_CTX);
        let keypair: Keypair;
		let keypair_bytes: [u8;96] = [74,83,195,251,188,89,151,14,229,248,90,248,19,135,93,255,193,58,144,74,46,83,174,126,101,250,13,234,110,98,201,1,159,7,231,190,85,81,56,122,152,186,151,124,115,45,8,13,203,15,41,160,72,227,101,105,18,198,83,62,50,238,122,237,156,102,163,57,200,52,79,146,47,195,32,108,181,218,232,20,165,148,192,23,125,211,35,92,37,77,156,64,154,101,184,8];
		let message:[u8;12] = [116,101,115,116,32,109,101,115,115,97,103,101];
		let signature_bytes:[u8;64] = [79,181,251,131,123,104,226,50,24,126,161,104,68,87,139,213,9,38,177,5,32,243,173,134,203,157,193,119,141,137,180,5,61,9,29,123,200,159,44,182,95,88,238,141,82,100,161,222,74,28,169,151,226,29,35,130,179,216,1,57,57,138,28,133];
		let good: &[u8] = "test message".as_bytes();
				
		let signature = match Signature::from_bytes(&signature_bytes[..])
						{
							Ok(some_sig)=>some_sig,
							Err(_)=>return signature_bytes.len()
						};
		//return 9;
        keypair  = Keypair::from_bytes(&keypair_bytes[..]).unwrap();

		 let message2: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
    	 let signature2: Signature = keypair.sign(context.bytes(message2));

		 {4}


	  /* if keypair.verify(context.bytes(&good), &signature).is_ok()
    		{2}
	   else
	   		{3}*/
}

/// Sign a message
///
/// The combination of both public and private key must be provided.
/// This is effectively equivalent to a keypair.
///
/// * public: UIntArray with 32 element
/// * private: UIntArray with 64 element
/// * message: Arbitrary length UIntArray
///
/// * returned vector is the signature consisting of 64 bytes.
  
#[no_mangle]
pub unsafe extern "C" fn schnr_sign(puk:*const u8,pri:*const u8,msg:*const u8,msg_len:usize) -> (Box<sr_data>) {

	//assert!(!pri.is_null(), "Null pointer in sum()");
	//assert!(!puk.is_null(), "Null pointer in sum()");
	//assert!(!msg.is_null(), "Null pointer in sum()");

	let rpri: &[u8] = slice::from_raw_parts(pri, 64);
	let rpuk: &[u8] = slice::from_raw_parts(puk, 32);
	let rmsg: &[u8] = slice::from_raw_parts(msg, msg_len);

	__sign(rpuk,rpri,rmsg);
	
	//let data_bytes = Bytes::from(__sign(rpuk,rpri,rmsg).to_vec());

	let mut data:[u8;96] = [0;96];
	let status:u32 = STATUS_OK;
	let len : u32 = PUB_KEY_LEN+PRI_KEY_LEN;

	let mut i =0;
	while i<64 {
	//	data[i] = data_bytes[i];
		i = i+1;
	}
	let sr_data = sr_data { data: data,len:len, status:status};
	Box::new(sr_data)
}

/// Verify a message and its corresponding against a public key;
///
/// * signature: UIntArray with 64 element
/// * message: Arbitrary length UIntArray
/// * pubkey: UIntArray with 32 element

#[no_mangle]
pub unsafe extern "C" fn schnr_verify(sign:*const u8,puk:*const u8,msg:*const u8,msg_len:usize) -> u32 {

	//assert!(!sign.is_null(), "Null pointer in sum()");
	//assert!(!puk.is_null(), "Null pointer in sum()");
	//assert!(!msg.is_null(), "Null pointer in sum()");

	let rsign: &[u8] = slice::from_raw_parts(sign, 64);
	let rpuk: &[u8] = slice::from_raw_parts(puk, 32);
	let rmsg: &[u8] = slice::from_raw_parts(msg, msg_len);

	match __verify(rsign, rmsg, rpuk){
		true => 1,
		false => 0,
	}
}

/// Generate a secret key (aka. private key) from a seed phrase.
///
/// * seed: UIntArray with 32 element
///
/// returned vector is the private key consisting of 64 bytes.

#[no_mangle]
pub unsafe extern "C" fn schnr_secret_from_seed(seed:*const u8) -> (Box<sr_data>) {

	assert!(!seed.is_null(), "Null pointer in sum()");

	let rseed: &[u8] = slice::from_raw_parts(seed, 32);
	
	__secret_from_seed(rseed);
	//let data_bytes = Bytes::from(__secret_from_seed(rseed).to_vec());

	let len : u32 = PUB_KEY_LEN+PRI_KEY_LEN;
	let mut data:[u8;96] = [0;96];
	let status:u32 = STATUS_OK;

	let mut i =0;
	while i<64 {
		//data[i] = data_bytes[i];
		i = i+1;
	}

	let sr_data = sr_data { data: data,len:len, status:status};
	Box::new(sr_data)
}
/// Generate a key pair. .
///
/// * seed: UIntArray with 32 element
///
/// returned vector is the concatenation of first the private key (64 bytes)
/// followed by the public key (32) bytes.

#[no_mangle]
pub unsafe extern "C" fn schnr_keypair_from_seed(seed:*const u8) -> (Box<sr_data>) {

	assert!(!seed.is_null(), "Null pointer in sum()");

	let rseed: &[u8] = slice::from_raw_parts(seed, 32);
	//let data_bytes = Bytes::from(__keypair_from_seed(rseed).to_vec());
	let mut data:[u8;96] = [0;96];
	let status:u32 = STATUS_OK;
	let len : u32 = PUB_KEY_LEN+PRI_KEY_LEN;

	let mut i =0;
	while i<96 {
	//	data[i] = data_bytes[i];
		i = i+1;
	}

	let sr_data = sr_data { data, len, status};
	Box::new(sr_data) 
}




#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[alloc_error_handler]
fn foo(_: core::alloc::Layout) -> ! {
    loop {}
}