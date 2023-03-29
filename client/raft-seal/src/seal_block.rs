// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Block sealing utilities

use crate::{rpc, ConsensusDataProvider, CreatedBlock, Error};
use codec::{Decode, Encode};
use futures::prelude::*;
use sc_consensus::{BlockImport, BlockImportParams, ForkChoiceStrategy, ImportResult, StateAction};
use sc_transaction_pool_api::TransactionPool;
use sp_api::{ProvideRuntimeApi, TransactionFor};
use sp_blockchain::HeaderBackend;
use sp_consensus::{self, BlockOrigin, Environment, Proposer, SelectChain};
use sp_consensus_raft::{digests::CompatibleDigestItem, RaftApi};
use sp_core::crypto::{ByteArray, Pair, Public};
use sp_inherents::{CreateInherentDataProviders, InherentDataProvider};
use sp_keystore::CryptoStore;
use sp_runtime::{
	app_crypto::{AppKey, AppPublic},
	traits::{Block as BlockT, Header as HeaderT, Member},
	DigestItem,
};
use std::{collections::HashMap, fmt::Debug, hash::Hash, sync::Arc, time::Duration};

/// max duration for creating a proposal in secs
pub const MAX_PROPOSAL_DURATION: u64 = 10;

pub type AuthorityId<P> = <P as Pair>::Public;

/// params for sealing a new block
pub struct SealBlockParams<'a, B: BlockT, BI, SC, C: ProvideRuntimeApi<B>, E, TP, CIDP, P> {
	/// if true, empty blocks(without extrinsics) will be created.
	/// otherwise, will return Error::EmptyTransactionPool.
	pub create_empty: bool,
	/// instantly finalize this block?
	pub finalize: bool,
	/// specify the parent hash of the about-to-created block
	pub parent_hash: Option<<B as BlockT>::Hash>,
	/// sender to report errors/success to the rpc.
	pub sender: rpc::Sender<CreatedBlock<<B as BlockT>::Hash>, B>,
	/// transaction pool
	pub pool: Arc<TP>,
	/// header backend
	pub client: Arc<C>,
	/// Environment trait object for creating a proposer
	pub env: &'a mut E,
	/// SelectChain object
	pub select_chain: &'a SC,
	/// Digest provider for inclusion in blocks.
	pub consensus_data_provider:
		Option<&'a dyn ConsensusDataProvider<B, Proof = P, Transaction = TransactionFor<C, B>>>,
	/// block import object
	pub block_import: &'a mut BI,
	/// Something that can create the inherent data providers.
	pub create_inherent_data_providers: &'a CIDP,
	/// The signature keystore.
	pub keystore: Arc<dyn CryptoStore>,
}

/// seals a new block with the given params
pub async fn seal_block<B, BI, SC, C, E, TP, CIDP, P, PP>(
	SealBlockParams {
		create_empty,
		finalize,
		pool,
		parent_hash,
		client,
		select_chain,
		block_import,
		env,
		create_inherent_data_providers,
		consensus_data_provider: digest_provider,
		mut sender,
		keystore,
		..
	}: SealBlockParams<'_, B, BI, SC, C, E, TP, CIDP, P>,
) where
	B: BlockT,
	BI: BlockImport<B, Error = sp_consensus::Error, Transaction = sp_api::TransactionFor<C, B>>
		+ Send
		+ Sync
		+ 'static,
	C: HeaderBackend<B> + ProvideRuntimeApi<B>,
	E: Environment<B>,
	E::Proposer: Proposer<B, Proof = P, Transaction = TransactionFor<C, B>>,
	TP: TransactionPool<Block = B>,
	SC: SelectChain<B>,
	TransactionFor<C, B>: 'static,
	CIDP: CreateInherentDataProviders<B, ()>,
	P: Send + Sync + 'static,
	C::Api: RaftApi<B, AuthorityId<PP>>,
	PP: Pair + Send + Sync,
	PP::Public: AppPublic + Public + Member + Encode + Decode + Hash,
	PP::Signature: TryFrom<Vec<u8>> + Member + Encode + Decode + Hash + Debug,
{
	let future = async {
		if pool.status().ready == 0 && !create_empty {
			return Err(Error::EmptyTransactionPool)
		}

		// get the header to build this new block on.
		// use the parent_hash supplied via `EngineCommand`
		// or fetch the best_block.
		let parent = match parent_hash {
			Some(hash) =>
				client.header(hash)?.ok_or_else(|| Error::BlockNotFound(format!("{}", hash)))?,
			None => select_chain.best_chain().await?,
		};

		let inherent_data_providers = create_inherent_data_providers
			.create_inherent_data_providers(parent.hash(), ())
			.await
			.map_err(|e| Error::Other(e))?;

		let inherent_data = inherent_data_providers.create_inherent_data().await?;

		let proposer = env.init(&parent).map_err(|err| Error::StringError(err.to_string())).await?;
		let inherents_len = inherent_data.len();

		let digest = if let Some(digest_provider) = digest_provider {
			digest_provider.create_digest(&parent, &inherent_data)?
		} else {
			Default::default()
		};

		let proposal = proposer
			.propose(
				inherent_data.clone(),
				digest,
				Duration::from_secs(MAX_PROPOSAL_DURATION),
				None,
			)
			.map_err(|err| Error::StringError(err.to_string()))
			.await?;

		if proposal.block.extrinsics().len() == inherents_len && !create_empty {
			return Err(Error::EmptyTransactionPool)
		}

		let (header, body) = proposal.block.deconstruct();
		let proof = proposal.proof;
		let mut params = BlockImportParams::new(BlockOrigin::Own, header.clone());
		params.body = Some(body);
		params.finalized = finalize;
		params.fork_choice = Some(ForkChoiceStrategy::LongestChain);
		params.state_action = StateAction::ApplyChanges(sc_consensus::StorageChanges::Changes(
			proposal.storage_changes,
		));

		let runtime_api = client.runtime_api();

		let authorities: Vec<AuthorityId<PP>> = runtime_api
			.authorities(parent.hash())
			.ok()
			.ok_or(sp_consensus::Error::InvalidAuthoritiesSet)?;

		let mut key: Option<AuthorityId<PP>> = None;

		for a in &authorities {
			let exists =
				keystore.has_keys(&[(a.to_raw_vec(), sp_consensus_raft::RAFT_KEY_TYPE)]).await;
			if exists {
				key = Some(a.clone());
				break
			}
		}

		let key = key.ok_or_else(|| {
			sp_consensus::Error::CannotSign(
				vec![],
				format!(
					"Could not find key in keystore that would match any known authority: {:?}",
					authorities
				),
			)
		})?;

		let public_type_pair = key.to_public_crypto_pair();
		let public = key.to_raw_vec();
		let signature = keystore
			.sign_with(<AuthorityId<PP> as AppKey>::ID, &public_type_pair, header.hash().as_ref())
			.await
			.map_err(|e| sp_consensus::Error::CannotSign(public.clone(), e.to_string()))?
			.ok_or_else(|| {
				sp_consensus::Error::CannotSign(
					public.clone(),
					"Could not find key in keystore.".into(),
				)
			})?;
		let signature = signature
			.clone()
			.try_into()
			.map_err(|_| sp_consensus::Error::InvalidSignature(signature, public))?;

		let signature_digest_item =
			<DigestItem as CompatibleDigestItem<PP::Signature>>::raft_seal(signature);
		params.post_digests.push(signature_digest_item);

		if let Some(digest_provider) = digest_provider {
			digest_provider.append_block_import(&parent, &mut params, &inherent_data, proof)?;
		}

		// Make sure we return the same post-hash that will be calculated when importing the block
		// This is important in case the digest_provider added any signature, seal, ect.
		let mut post_header = header.clone();
		post_header.digest_mut().logs.extend(params.post_digests.iter().cloned());

		match block_import.import_block(params, HashMap::new()).await? {
			ImportResult::Imported(aux) =>
				Ok(CreatedBlock { hash: <B as BlockT>::Header::hash(&post_header), aux }),
			other => Err(other.into()),
		}
	};

	rpc::send_result(&mut sender, future.await)
}
