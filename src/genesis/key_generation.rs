
use secp256k1::{Secp256k1};
use secp256k1::key::{SecretKey, PublicKey};

use rand::{thread_rng};


pub fn generate_keypair() -> (SecretKey, PublicKey) {

	let mut secp = Secp256k1::new();
    secp.randomize(&mut thread_rng());

    let (sk, pk) = secp.generate_keypair(&mut thread_rng()).ok().expect("error generating keys");

    (sk, pk)
}