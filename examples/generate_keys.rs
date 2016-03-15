extern crate safex;
extern crate rustc_serialize;

extern crate bitcoin;

use std::str;
use rustc_serialize::hex::FromHex;


use safex::genesis::key_generation::KeyPair;

fn main() {
	let our_key = KeyPair::create().ok().expect("error");
	
	let the_secret = KeyPair::private_key_tobase64(our_key.secret);
	print!("your base64 private key {:?} \n", the_secret);

	let the_string = KeyPair::address_base58(our_key.public);
	print!("your Hash160 Public Key: {:?} \n", the_string);


	let the_keys = KeyPair::from_secret(our_key.secret).unwrap();
	let the_secret = KeyPair::private_key_tobase64(the_keys.secret);
	print!("your base64 private key {:?} \n", the_secret);

	let the_string = KeyPair::address_base58(the_keys.public);
	print!("your Hash160 Public Key: {:?} \n", the_string);


	
}