use bip32::{
	Error as Bip32Error, ExtendedPrivateKey, PrivateKey as PrivateKeyT, PrivateKeyBytes,
	PublicKey as PublicKeyT, PublicKeyBytes,
};
use bip39::{Language, Mnemonic, Seed};
use libsecp256k1::{PublicKey, PublicKeyFormat, SecretKey};
use log::debug;
use node_template_runtime::{
	AccountId, AuraConfig, BalancesConfig, GenesisConfig, GrandpaConfig, Signature, SudoConfig,
	SystemConfig, WASM_BINARY,
};
use sc_service::ChainType;
use sha3::{Digest, Keccak256};
use sp_consensus_aura::sr25519::AuthorityId as AuraId;
use sp_core::{ecdsa, Pair, Public, H160, H256};
use sp_finality_grandpa::AuthorityId as GrandpaId;
use sp_runtime::traits::{IdentifyAccount, Verify};

// The URL for the telemetry server.
// const STAGING_TELEMETRY_URL: &str = "wss://telemetry.polkadot.io/submit/";

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec<GenesisConfig>;

/// Generate a crypto pair from seed.
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
	TPublic::Pair::from_string(&format!("//{}", seed), None)
		.expect("static values are valid; qed")
		.public()
}

type AccountPublic = <Signature as Verify>::Signer;

/// Generate an account ID from seed.
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
	AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
	AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Generate an Aura authority key.
pub fn authority_keys_from_seed(s: &str) -> (AuraId, GrandpaId) {
	(get_from_seed::<AuraId>(s), get_from_seed::<GrandpaId>(s))
}

pub fn development_config() -> Result<ChainSpec, String> {
	let wasm_binary = WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?;

	Ok(ChainSpec::from_genesis(
		// Name
		"Development",
		// ID
		"dev",
		ChainType::Development,
		move || {
			// The moonbeam seed.
			let accounts = generate_accounts(
				"bottom drive obey lake curtain smoke basket hold race lonely fit walk".into(),
				10,
			);

			testnet_genesis(
				wasm_binary,
				// Initial PoA authorities
				vec![authority_keys_from_seed("Alice")],
				// Sudo account
				get_account_id_from_seed::<ecdsa::Public>("Alice"),
				// Pre-funded accounts
				accounts,
				true,
			)
		},
		// Bootnodes
		vec![],
		// Telemetry
		None,
		// Protocol ID
		None,
		None,
		// Properties
		None,
		// Extensions
		None,
	))
}

// `libsecp256k1::PublicKey` wrapped type
pub struct Secp256k1PublicKey(pub PublicKey);
// `libsecp256k1::Secret`  wrapped type
pub struct Secp256k1SecretKey(pub SecretKey);

impl PublicKeyT for Secp256k1PublicKey {
	fn from_bytes(bytes: PublicKeyBytes) -> Result<Self, Bip32Error> {
		let public = PublicKey::parse_compressed(&bytes).map_err(|_| return Bip32Error::Decode)?;
		Ok(Self(public))
	}

	fn to_bytes(&self) -> PublicKeyBytes {
		self.0.serialize_compressed()
	}

	fn derive_child(&self, other: PrivateKeyBytes) -> Result<Self, Bip32Error> {
		let mut child = self.0.clone();
		let secret = SecretKey::parse(&other).map_err(|_| return Bip32Error::Decode)?;
		let _ = child.tweak_add_assign(&secret);
		Ok(Self(child))
	}
}

impl PrivateKeyT for Secp256k1SecretKey {
	type PublicKey = Secp256k1PublicKey;

	fn from_bytes(bytes: &PrivateKeyBytes) -> Result<Self, Bip32Error> {
		let secret = SecretKey::parse(&bytes).map_err(|_| return Bip32Error::Decode)?;
		Ok(Self(secret))
	}

	fn to_bytes(&self) -> PrivateKeyBytes {
		self.0.serialize()
	}

	fn derive_child(&self, other: PrivateKeyBytes) -> Result<Self, Bip32Error> {
		let mut child = self.0.clone();
		let secret = SecretKey::parse(&other).map_err(|_| return Bip32Error::Decode)?;
		let _ = child.tweak_add_assign(&secret);
		Ok(Self(child))
	}

	fn public_key(&self) -> Self::PublicKey {
		Secp256k1PublicKey(PublicKey::from_secret_key(&self.0))
	}
}

pub fn derive_bip44_pairs_from_mnemonic<TPublic: Public>(
	mnemonic: &str,
	num_accounts: u32,
) -> Vec<TPublic::Pair> {
	let seed = Mnemonic::from_phrase(mnemonic, Language::English)
		.map(|x| Seed::new(&x, ""))
		.expect("Wrong mnemonic provided");

	let mut childs = Vec::new();
	for i in 0..num_accounts {
		if let Some(child_pair) = format!("m/44'/60'/0'/0/{}", i)
			.parse()
			.ok()
			.and_then(|derivation_path| {
				ExtendedPrivateKey::<Secp256k1SecretKey>::derive_from_path(&seed, &derivation_path)
					.ok()
			})
			.and_then(|extended| {
				TPublic::Pair::from_seed_slice(&extended.private_key().0.serialize()).ok()
			}) {
			childs.push(child_pair);
		} else {
			log::error!("An error ocurred while deriving key {} from parent", i)
		}
	}
	childs
}

/// Helper function to get an `AccountId` from an ECDSA Key Pair.
pub fn get_account_id_from_pair(pair: ecdsa::Pair) -> Option<AccountId> {
	let decompressed = PublicKey::parse_slice(&pair.public().0, Some(PublicKeyFormat::Compressed))
		.ok()?
		.serialize();

	let mut m = [0u8; 64];
	m.copy_from_slice(&decompressed[1..65]);

	Some(H160::from(H256::from_slice(Keccak256::digest(&m).as_slice())).into())
}

pub fn generate_accounts(mnemonic: String, num_accounts: u32) -> Vec<AccountId> {
	let childs = derive_bip44_pairs_from_mnemonic::<ecdsa::Public>(&mnemonic, num_accounts);
	debug!("Account Generation");
	childs
		.iter()
		.filter_map(|par| {
			let account = get_account_id_from_pair(par.clone());
			debug!(
				"private_key {} --------> Account {:x?}",
				sp_core::hexdisplay::HexDisplay::from(&par.clone().seed()),
				account
			);
			account
		})
		.collect()
}

pub fn local_testnet_config() -> Result<ChainSpec, String> {
	let wasm_binary = WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?;

	Ok(ChainSpec::from_genesis(
		// Name
		"Local Testnet",
		// ID
		"local_testnet",
		ChainType::Local,
		move || {
			let accounts = generate_accounts(
				"bottom drive obey lake curtain smoke basket hold race lonely fit walk".into(),
				10,
			);

			testnet_genesis(
				wasm_binary,
				// Initial PoA authorities
				vec![authority_keys_from_seed("Alice"), authority_keys_from_seed("Bob")],
				// Sudo account
				get_account_id_from_seed::<ecdsa::Public>("Alice"),
				// Pre-funded accounts
				accounts,
				true,
			)
		},
		// Bootnodes
		vec![],
		// Telemetry
		None,
		// Protocol ID
		None,
		// Properties
		None,
		None,
		// Extensions
		None,
	))
}

/// Configure initial storage state for FRAME modules.
fn testnet_genesis(
	wasm_binary: &[u8],
	initial_authorities: Vec<(AuraId, GrandpaId)>,
	root_key: AccountId,
	endowed_accounts: Vec<AccountId>,
	_enable_println: bool,
) -> GenesisConfig {
	GenesisConfig {
		system: SystemConfig {
			// Add Wasm runtime to storage.
			code: wasm_binary.to_vec(),
		},
		balances: BalancesConfig {
			// Configure endowed accounts with initial balance of 1 << 60.
			balances: endowed_accounts.iter().cloned().map(|k| (k, 1 << 60)).collect(),
		},
		aura: AuraConfig {
			authorities: initial_authorities.iter().map(|x| (x.0.clone())).collect(),
		},
		grandpa: GrandpaConfig {
			authorities: initial_authorities.iter().map(|x| (x.1.clone(), 1)).collect(),
		},
		sudo: SudoConfig {
			// Assign network admin rights.
			key: Some(root_key),
		},
		transaction_payment: Default::default(),
	}
}
