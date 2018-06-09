use model::bundle::{self, Bundle};
use model::transaction::Transaction;
use pow::kerl::{self, Kerl};
use pow::traits::{ICurl, HASH_LENGTH};
use utils::constants;
use utils::converter::{self, array_copy};
use utils::input_validator;

const KEY_LENGTH: usize = 6561;

pub fn key(in_seed: &[i32], index: usize, security: usize) -> Vec<i32> {
    if security < 1 {
        panic!(constants::INVALID_SECURITY_LEVEL_INPUT_ERROR);
    }
    let mut seed = in_seed.to_owned();
    for i in 0..index {
        for trit in &mut seed {
            *trit += 1;
            if *trit > 1 {
                *trit = -1;
            } else {
                break;
            }
        }
    }
    let mut curl = Kerl::default();
    curl.reset();
    curl.absorb(&seed);
    curl.squeeze(&mut seed);
    curl.reset();
    curl.absorb(&seed);

    let mut key = vec![0; (security * HASH_LENGTH * 27) as usize];
    let mut buffer = vec![0; seed.len()];
    let mut offset = 0;

    let mut tmp_sec = security;
    while tmp_sec > 0 {
        for i in 0..27 {
            curl.squeeze(&mut buffer);
            array_copy(&buffer, 0, &mut key, offset, HASH_LENGTH);
            offset += HASH_LENGTH;
        }
        tmp_sec -= 1;
    }
    key
}

pub fn signature_fragment(normalized_bundle_fragment: &[i32], key_fragment: &[i32]) -> Vec<i32> {
    let mut signature_fragment = key_fragment.to_owned();
    let mut curl = Kerl::default();
    for (i, fragment) in normalized_bundle_fragment.iter().enumerate().take(27) {
        let mut j = 0;
        while j < 13 - fragment {
            curl.reset();
            curl.absorb_offset(&signature_fragment, i * HASH_LENGTH, HASH_LENGTH);
            curl.squeeze_offset(&mut signature_fragment, i * HASH_LENGTH, HASH_LENGTH);
            j += 1;
        }
    }
    signature_fragment
}

pub fn address(digests: &[i32]) -> [i32; HASH_LENGTH] {
    let mut address = [0; HASH_LENGTH];
    let mut curl = Kerl::default();
    curl.reset();
    curl.absorb(&digests);
    curl.squeeze(&mut address);
    address
}

pub fn digests(key: &[i32]) -> Vec<i32> {
    let security = (key.len() as f64 / KEY_LENGTH as f64).floor() as usize;
    let mut digests = vec![0; security * HASH_LENGTH];
    let mut key_fragment = [0; KEY_LENGTH];
    let mut curl = Kerl::default();
    for i in 0..security {
        array_copy(&key, i * KEY_LENGTH, &mut key_fragment, 0, KEY_LENGTH);
        for j in 0..27 {
            for k in 0..26 {
                curl.reset();
                curl.absorb_offset(&key_fragment, j * HASH_LENGTH, HASH_LENGTH);
                curl.squeeze_offset(&mut key_fragment, j * HASH_LENGTH, HASH_LENGTH);
            }
        }
        curl.reset();
        curl.absorb(&key_fragment);
        curl.squeeze_offset(&mut digests, i * HASH_LENGTH, HASH_LENGTH);
    }
    digests
}

pub fn digest(normalized_bundle_fragment: &[i32], signature_fragment: &[i32]) -> Vec<i32> {
    let mut curl = Kerl::default();
    curl.reset();
    let mut j_curl = Kerl::default();
    let mut buffer = vec![0; HASH_LENGTH];
    for i in 0..27 {
        buffer = signature_fragment[i * HASH_LENGTH..(i + 1) * HASH_LENGTH].to_vec();
        let mut j = normalized_bundle_fragment[i] + 13;
        while j > 0 {
            j_curl.reset();
            j_curl.absorb(&buffer);
            j_curl.squeeze(&mut buffer);
            j -= 1;
        }
        curl.absorb(&buffer);
    }
    curl.squeeze(&mut buffer);
    buffer
}

pub fn validate_bundle_signatures(signed_bundle: &Bundle, address: &str) -> bool {
    let mut bundle_hash = String::new();
    let mut trx: Transaction;
    let mut signature_fragments: Vec<String> = Vec::new();

    for i in 0..signed_bundle.transactions().len() {
        trx = signed_bundle.transactions()[i].clone();
        if trx.address().clone().unwrap() == address {
            bundle_hash = trx.bundle().clone().unwrap();
            let signature_fragment = trx.signature_fragments().clone().unwrap();
            if input_validator::is_nine_trytes(&signature_fragment, signature_fragment.len()) {
                break;
            }
            signature_fragments.push(signature_fragment);
        }
    }
    validate_signatures(address, &signature_fragments, &bundle_hash)
}

pub fn validate_signatures(
    expected_address: &str,
    signature_fragments: &[String],
    bundle_hash: &str,
) -> bool {
    let bundle = Bundle::default();
    let mut normalized_bundle_fragments = vec![vec![0; 3]; 27];
    let normalized_bundle_hash = bundle::normalized_bundle(bundle_hash);

    for i in 0..3 {
        normalized_bundle_fragments[i] = normalized_bundle_hash[i * 27..(i + 1) * 27].to_vec();
    }
    let mut digests = vec![0; signature_fragments.len() * HASH_LENGTH];

    for i in 0..signature_fragments.len() {
        let digest_buffer = digest(
            &normalized_bundle_fragments[i % 3],
            &converter::trits_from_string(&signature_fragments[i]),
        );
        array_copy(
            &digest_buffer,
            0,
            &mut digests,
            i * HASH_LENGTH,
            HASH_LENGTH,
        );
    }
    let address = converter::trytes(&address(&digests));
    expected_address == address
}
