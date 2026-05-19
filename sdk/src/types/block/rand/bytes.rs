// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use alloc::vec::Vec;

use rand::random;

/// Generates a [`Vec`] of random bytes with a given length.
pub fn rand_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|_| random::<u8>()).collect()
}

/// Generates an array of random bytes of length N.
pub fn rand_bytes_array<const N: usize>() -> [u8; N] {
    random::<[u8; N]>()
}
