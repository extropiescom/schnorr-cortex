// -*- mode: rust; -*-
//
// This file is part of schnorrkel for embedded C program.
// Copyright (c) 2019 Chester Lee @extropies.com
//
// Authors:
// - Chester Lee <chester@extropies.com>

// use alloc::boxed::Box;
// use core::panic::PanicInfo;
// use core::slice;

// use super::*;
//test functions
// #[no_mangle]
// pub unsafe extern "C" fn test_box(message: *const u8) -> *mut u8 {
// 	let rseed: &[u8] = slice::from_raw_parts(message, 96);
// 	let mut data: [u8; 96] = [0; 96];
// 	let status: u32 = 0;
// 	let len: usize = 96;
// 	let mut i = 0;
// 	while i < 96 {
// 		data[i] = rseed[i];
// 		i = i + 1;
// 	}

// 	let b = Box::new(data);
// 	return Box::into_raw(b) as *mut u8;
// }

// #[no_mangle]
// pub unsafe extern "C" fn test_sign_verify() -> u8 {
// 	const SIGNING_CTX: &'static [u8] = b"good";
// 	let context = signing_context(SIGNING_CTX);
// 	let keypair: Keypair;
// 	let keypair_bytes: [u8; 96] = [
// 		74, 83, 195, 251, 188, 89, 151, 14, 229, 248, 90, 248, 19, 135, 93, 255, 193, 58, 144, 74,
// 		46, 83, 174, 126, 101, 250, 13, 234, 110, 98, 201, 1, 159, 7, 231, 190, 85, 81, 56, 122,
// 		152, 186, 151, 124, 115, 45, 8, 13, 203, 15, 41, 160, 72, 227, 101, 105, 18, 198, 83, 62,
// 		50, 238, 122, 237, 156, 102, 163, 57, 200, 52, 79, 146, 47, 195, 32, 108, 181, 218, 232,
// 		20, 165, 148, 192, 23, 125, 211, 35, 92, 37, 77, 156, 64, 154, 101, 184, 8,
// 	];
// 	let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
// 	keypair = Keypair::from_bytes(&keypair_bytes[..]).unwrap();
// 	let signature: Signature = keypair.sign(context.bytes(message));
// 	if keypair.verify(context.bytes(&message), &signature).is_ok() {
// 		0
// 	} else {
// 		1
// 	}
// }

// #[no_mangle]
// pub unsafe extern "C" fn test_sign_ptr() -> *mut u8 {
// 	const SIGNING_CTX: &'static [u8] = b"good";
// 	let context = signing_context(SIGNING_CTX);
// 	let keypair: Keypair;
// 	let keypair_bytes: [u8; 96] = [
// 		74, 83, 195, 251, 188, 89, 151, 14, 229, 248, 90, 248, 19, 135, 93, 255, 193, 58, 144, 74,
// 		46, 83, 174, 126, 101, 250, 13, 234, 110, 98, 201, 1, 159, 7, 231, 190, 85, 81, 56, 122,
// 		152, 186, 151, 124, 115, 45, 8, 13, 203, 15, 41, 160, 72, 227, 101, 105, 18, 198, 83, 62,
// 		50, 238, 122, 237, 156, 102, 163, 57, 200, 52, 79, 146, 47, 195, 32, 108, 181, 218, 232,
// 		20, 165, 148, 192, 23, 125, 211, 35, 92, 37, 77, 156, 64, 154, 101, 184, 8,
// 	];
// 	let message: &[u8] = "This is a test of the tsunami alert system.".as_bytes();
// 	keypair = Keypair::from_bytes(&keypair_bytes[..]).unwrap();
// 	let signature: Signature = keypair.sign(context.bytes(message));
// 	let signature_bytes = signature.to_bytes();

// 	let mut data: [u8; 96] = [0; 96];

// 	let mut i = 0;
// 	while i < 64 {
// 		data[i] = signature_bytes[i];
// 		i = i + 1;
// 	}
// 	let b = Box::new(data);
// 	return Box::into_raw(b) as *mut u8;
// }

// #[no_mangle]
// pub unsafe extern "C" fn test_verify() -> usize {
// 	const SIGNING_CTX: &'static [u8] = b"good";
// 	let context = signing_context(SIGNING_CTX);
// 	let keypair: Keypair;
// 	let keypair_bytes: [u8; 96] = [
// 		74, 83, 195, 251, 188, 89, 151, 14, 229, 248, 90, 248, 19, 135, 93, 255, 193, 58, 144, 74,
// 		46, 83, 174, 126, 101, 250, 13, 234, 110, 98, 201, 1, 159, 7, 231, 190, 85, 81, 56, 122,
// 		152, 186, 151, 124, 115, 45, 8, 13, 203, 15, 41, 160, 72, 227, 101, 105, 18, 198, 83, 62,
// 		50, 238, 122, 237, 156, 102, 163, 57, 200, 52, 79, 146, 47, 195, 32, 108, 181, 218, 232,
// 		20, 165, 148, 192, 23, 125, 211, 35, 92, 37, 77, 156, 64, 154, 101, 184, 8,
// 	];
// 	let signature_bytes: [u8; 64] = [
// 		79, 181, 251, 131, 123, 104, 226, 50, 24, 126, 161, 104, 68, 87, 139, 213, 9, 38, 177, 5,
// 		32, 243, 173, 134, 203, 157, 193, 119, 141, 137, 180, 5, 61, 9, 29, 123, 200, 159, 44, 182,
// 		95, 88, 238, 141, 82, 100, 161, 222, 74, 28, 169, 151, 226, 29, 35, 130, 179, 216, 1, 57,
// 		57, 138, 28, 133,
// 	];
// 	let good: &[u8] = "test message".as_bytes();

// 	let signature = match Signature::from_bytes(&signature_bytes[..]) {
// 		Ok(some_sig) => some_sig,
// 		Err(_) => return signature_bytes.len(),
// 	};
// 	keypair = Keypair::from_bytes(&keypair_bytes[..]).unwrap();

// 	if keypair.verify(context.bytes(&good), &signature).is_ok() {
// 		0
// 	} else {
// 		1
// 	}
// }
