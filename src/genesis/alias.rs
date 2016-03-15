

use secp256k1::{Secp256k1};
use secp256k1::key::{SecretKey, PublicKey};

use rand::{thread_rng};




struct Account {
	identities: Vec<Alias>,
}


impl Account {
	/*fn new_account() -> Account {

	}*/
}




struct Alias {
	name: String,
	keys: Vec<Keys>,
	
}







struct Keys {
	name: String,
	pub_key: PublicKey,
	sec_key: SecretKey,
}


impl Keys {
	/*fn generate_keys() -> Keys {
		
	}*/
}



