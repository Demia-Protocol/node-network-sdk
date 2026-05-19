// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use rand::{
    Rng,
    distributions::{
        Distribution, Standard,
        uniform::{SampleRange, SampleUniform},
    },
    random,
};

/// Generates a random number.
pub fn rand_number<T>() -> T
where
    Standard: Distribution<T>,
{
    random()
}

/// Generates a random number within a given range.
pub fn rand_number_range<T, R>(range: R) -> T
where
    T: SampleUniform + PartialOrd,
    R: SampleRange<T>,
{
    rand::thread_rng().gen_range(range)
}
