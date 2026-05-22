// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "serde")]
pub mod serde;

#[cfg(feature = "web-time")]
pub fn unix_timestamp_now() -> core::time::Duration {
    web_time::SystemTime::now()
        .duration_since(web_time::SystemTime::UNIX_EPOCH)
        .expect("time went backwards")
}
