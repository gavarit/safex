extern crate safex;

use safex::genesis::key_generation::generate_keypair;

fn main() {

	let (sk, pk) = generate_keypair();
	print!("secret key {:?} \n", sk);
	print!("public key {:?}", pk);
}