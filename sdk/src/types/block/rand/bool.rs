// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use rand::{random, Rng};

/// Generates a random boolean.
pub fn rand_bool() -> bool {
    random::<bool>()
}
