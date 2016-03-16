

use secp256k1::{Secp256k1};
use secp256k1::key::{SecretKey, PublicKey};

use rand::{thread_rng};


use genesis::key_generation::KeyPair;

//every alias gets a keypair

struct Account {
	identities: Vec<Alias>,
}


impl Account {
	/*fn new_account() -> Account {

	}*/
}




struct Alias {
	name: String,
	keys: Vec<KeyPair>,

}






