use rustc_serialize::base64::{self, ToBase64, STANDARD};
use rustc_serialize::hex::FromHex;


use secp256k1::{key, Secp256k1};
use secp256k1::key::{SecretKey, PublicKey};
//use secp256k1::Signature::from_der;

use rand::os::OsRng;

use bitcoin::util::hash::Hash160;
use bitcoin::util::address::Address;
use bitcoin::network::constants::Network::Bitcoin;
use bitcoin::util::address::Type::PubkeyHash;
use bitcoin::util::hash::Sha256dHash;

lazy_static! {
	static ref SECP256K1: Secp256k1 = Secp256k1::new();
}

pub type Sig = String;


#[derive(Debug)]
pub enum KeyError {
	SomethingIsWrong,
	InvalidMessage,
	InvalidPublic,
	InvalidSecret,
	InvalidSignature,
	Io(::std::io::Error),
}

pub type KeyResult = Result<KeyPair, KeyError>;


impl From<::secp256k1::Error> for KeyError {
	fn from(e: ::secp256k1::Error) -> KeyError {
		match e {
			::secp256k1::Error::InvalidMessage => KeyError::InvalidMessage,
			::secp256k1::Error::InvalidPublicKey => KeyError::InvalidPublic,
			::secp256k1::Error::InvalidSecretKey => KeyError::InvalidSecret,
			_ => KeyError::InvalidSignature,
		}
	}
}

impl From<::std::io::Error> for KeyError {
	fn from(err: ::std::io::Error) -> KeyError {
		KeyError::Io(err)
	}
}
 
pub struct KeyPair {
	pub public: PublicKey,
	pub secret: SecretKey
}


impl KeyPair {
	//get the public key from the secret - import a secretkey get a KeyPair object
	pub fn from_secret(secret: SecretKey) -> KeyResult {
		let context = &SECP256K1;
		let s: key::SecretKey = secret;
		let pub_key = try!(key::PublicKey::from_secret_key(context, &s));
		Ok(KeyPair {
			secret: secret,
			public: pub_key,
		})
	}
	//make a new random keypair
	pub fn create() -> KeyResult {
		let context = &SECP256K1;
		let mut rng = try!(OsRng::new());
		let (sk, pk) = try!(context.generate_keypair(&mut rng));
		let p: PublicKey = unsafe { ::std::mem::transmute(pk) };
		let s: SecretKey = unsafe { ::std::mem::transmute(sk) };
		let out_keys = KeyPair {
			public: p,
			secret: s,
		};
		Ok(out_keys)
	}
	//convert secret key to base64 for ready import to wallets
	pub fn private_key_tobase64(secret: SecretKey) -> String {
		let mut format_sk = format!("{:?}", secret);
    	let string_len = format_sk.len() - 1;
    	format_sk.remove(string_len);
    	for i in 0..10 {
        	format_sk.remove(0);
    	}
    	let sec_key_base64 = format_sk.from_hex().ok().expect("error converting secret to base64").to_base64(STANDARD);
    	sec_key_base64
	}
	//extract a bitcoin valid address in base58
	pub fn address_base58(public: PublicKey) -> String {
		let context = &SECP256K1;
		let the_addr = Address { 
      		ty: PubkeyHash, 
      		network: Bitcoin, 
      		hash: Hash160::from_data(&public.serialize_vec(&context, false)[..]),
  		};

  		let return_this: String = format!("{:?}", the_addr);
  		return_this
	}

	/// Returns public key
	pub fn public(&self) -> &PublicKey {
		&self.public
	}
	/// Returns private key
	pub fn secret(&self) -> &SecretKey {
		&self.secret
	}
	//pub fn publick_key(&self) -> &

	pub fn sign(secret: &SecretKey, message: Vec<u8>) {
		use secp256k1::*;
		let context = &SECP256K1;
		let sec: &key::SecretKey = unsafe { ::std::mem::transmute(secret) };
		let signature_hash = Sha256dHash::from_data(&message[..]);
		let msg = Message::from_slice(&signature_hash[..]).unwrap();

		let s = context.sign_recoverable(&msg, sec).unwrap();
		let (rec_id, data) = s.serialize_compact(context);
		let th_sdata = Sha256dHash::from_data(&data[..]);
		println!("{:?}", th_sdata);
		//let mut signature = unsafe { ::std::mem::uninitialized() };
		//signature.clone_from_slice(&data);
		//signature[64] = rec_id.to_i32() as u8;
		//let signature_hash = &Sha256dHash::from_data(&message[..]);

	}
}


#[test]
fn test() {
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
	let this_strings = "hello".to_string();

	let mut this_vec: Vec<u8> = Vec::new();
	this_vec.push(0);
	KeyPair::sign(&the_keys.secret, this_vec);
}