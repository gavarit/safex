use rustc_serialize::base64::{self, ToBase64, STANDARD};
use rustc_serialize::hex::FromHex;

use secp256k1::{key, Secp256k1};
use secp256k1::key::{SecretKey, PublicKey};

use rand::os::OsRng;

use bitcoin::util::hash::Hash160;
use bitcoin::util::address::Address;
use bitcoin::network::constants::Network::Bitcoin;
use bitcoin::util::address::Type::PubkeyHash;

lazy_static! {
	static ref SECP256K1: Secp256k1 = Secp256k1::new();
}

pub type Signature = String;


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

}


/// EC functions
pub mod ec {
/*	/// Returns siganture of message hash.
	pub fn sign(secret: &SecretKey, message: &[u8]) -> Result<Signature, CryptoError> {
		// TODO: allow creation of only low-s signatures.
		use secp256k1::*;
		let context = &key_generation::SECP256K1;
		let sec: &key::SecretKey = unsafe { ::std::mem::transmute(secret) };
		let s = try!(context.sign_recoverable(&try!(Message::from_slice(&message)), sec));
		let (rec_id, data) = s.serialize_compact(context);
		let mut signature: crypto::Signature = unsafe { ::std::mem::uninitialized() };
		signature.clone_from_slice(&data);
		signature[64] = rec_id.to_i32() as u8;

		let (_, s, v) = signature.to_rsv();
		let secp256k1n = U256::from_str("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap();
		if !is_low_s(&s) {
			signature = super::Signature::from_rsv(&H256::from_slice(&signature[0..32]), &H256::from(secp256k1n - s), v ^ 1);
		}
		Ok(signature)
	}

	/// Recovers Public key from signed message hash.
	pub fn recover(signature: &Signature, message: &H256) -> PublicKey {
		use secp256k1::*;
		let context = &crypto::SECP256K1;
		let rsig = try!(RecoverableSignature::from_compact(context, &signature[0..64], try!(RecoveryId::from_i32(signature[64] as i32))));
		let publ = try!(context.recover(&try!(Message::from_slice(&message)), &rsig));
		let serialized = publ.serialize_vec(context, false);
		let p: Public = Public::from_slice(&serialized[1..65]);
		//TODO: check if it's the zero key and fail if so.
		Ok(p)
	}





	/// Verify signature.
	pub fn verify(public: &Public, signature: &Signature, message: &H256) -> Result<bool, CryptoError> {
		use secp256k1::*;
		let context = &crypto::SECP256K1;
		let rsig = try!(RecoverableSignature::from_compact(context, &signature[0..64], try!(RecoveryId::from_i32(signature[64] as i32))));
		let sig = rsig.to_standard(context);

		let mut pdata: [u8; 65] = [4u8; 65];
		let ptr = pdata[1..].as_mut_ptr();
		let src = public.as_ptr();
		unsafe { ::std::ptr::copy_nonoverlapping(src, ptr, 64) };
		let publ = try!(key::PublicKey::from_slice(context, &pdata));
		match context.verify(&try!(Message::from_slice(&message)), &sig, &publ) {
			Ok(_) => Ok(true),
			Err(Error::IncorrectSignature) => Ok(false),
			Err(x) => Err(<CryptoError as From<Error>>::from(x))
		}
*/

}

/*pub fn generate_keypair() -> (SecretKey, PublicKey) {

	let mut secp = Secp256k1::new();
    secp.randomize(&mut thread_rng());

    let (sk, pk) = secp.generate_keypair(&mut thread_rng()).ok().expect("error generating keys");

    (sk, pk)
}*/

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
}