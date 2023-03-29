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

//! A manual sealing engine: the engine listens for rpc calls to seal blocks and create forks.
//! This is suitable for a testing environment.

use codec::{Decode, Encode};
use futures::prelude::*;
use prometheus_endpoint::Registry;
use sc_client_api::backend::{Backend as ClientBackend, Finalizer};
use sc_consensus::{
	block_import::{BlockImport, BlockImportParams, ForkChoiceStrategy},
	import_queue::{BasicQueue, BoxBlockImport, Verifier},
};
use seal_block::AuthorityId;
use sp_blockchain::HeaderBackend;
use sp_consensus::{CacheKeyId, Environment, Proposer, SelectChain};
use sp_consensus_raft::RaftApi;
use sp_core::crypto::{Pair, Public};
use sp_inherents::CreateInherentDataProviders;
use sp_keystore::CryptoStore;
use sp_runtime::{
	app_crypto::AppPublic,
	traits::{Block as BlockT, Member},
	ConsensusEngineId,
};
use std::{fmt::Debug, hash::Hash, marker::PhantomData, sync::Arc, time::Duration};

mod error;
mod finalize_block;
mod seal_block;

pub mod consensus;
pub mod rpc;

pub use self::{
	consensus::ConsensusDataProvider,
	error::{raft_err, Error},
	finalize_block::{finalize_block, FinalizeBlockParams},
	rpc::{CreatedBlock, EngineCommand},
	seal_block::{seal_block, SealBlockParams, MAX_PROPOSAL_DURATION},
};
use sc_transaction_pool_api::TransactionPool;
use sp_api::{HeaderT, ProvideRuntimeApi, TransactionFor};

const LOG_TARGET: &str = "raft-seal";

/// The `ConsensusEngineId` of Manual Seal.
pub const MANUAL_SEAL_ENGINE_ID: ConsensusEngineId = [b'm', b'a', b'n', b'l'];

/// The verifier for the manual seal engine; instantly finalizes.
struct ManualSealVerifier;

#[async_trait::async_trait]
impl<B: BlockT> Verifier<B> for ManualSealVerifier {
	async fn verify(
		&mut self,
		mut block: BlockImportParams<B, ()>,
	) -> Result<(BlockImportParams<B, ()>, Option<Vec<(CacheKeyId, Vec<u8>)>>), String> {
		let hash = block.header.hash();
		let seal = block.header.digest_mut().pop().ok_or(Error::<B>::HeaderUnsealed(hash));
		if let Err(e) = seal {
			return Err(format!("{}", e))
		}
		let seal = seal.unwrap();
		// TODO: it'd be nice to actually verify the seal heh.
		// let sig = seal.as_raft_seal().ok_or_else(|| raft_err(Error::HeaderBadSeal(hash)))?;

		block.post_digests.push(seal);
		block.post_hash = Some(hash);

		block.finalized = false;
		block.fork_choice = Some(ForkChoiceStrategy::LongestChain);
		Ok((block, None))
	}
}

/// Instantiate the import queue for the manual seal consensus engine.
pub fn import_queue<Block, Transaction>(
	block_import: BoxBlockImport<Block, Transaction>,
	spawner: &impl sp_core::traits::SpawnEssentialNamed,
	registry: Option<&Registry>,
) -> BasicQueue<Block, Transaction>
where
	Block: BlockT,
	Transaction: Send + Sync + 'static,
{
	BasicQueue::new(ManualSealVerifier, block_import, None, spawner, registry)
}

/// Params required to start the instant sealing authorship task.
pub struct ManualSealParams<B: BlockT, BI, E, C: ProvideRuntimeApi<B>, TP, SC, CS, CIDP, P> {
	/// Block import instance for well. importing blocks.
	pub block_import: BI,

	/// The environment we are producing blocks for.
	pub env: E,

	/// Client instance
	pub client: Arc<C>,

	/// Shared reference to the transaction pool.
	pub pool: Arc<TP>,

	/// Stream<Item = EngineCommands>, Basically the receiving end of a channel for sending
	/// commands to the authorship task.
	pub commands_stream: CS,

	/// SelectChain strategy.
	pub select_chain: SC,

	/// Digest provider for inclusion in blocks.
	pub consensus_data_provider:
		Option<Box<dyn ConsensusDataProvider<B, Proof = P, Transaction = TransactionFor<C, B>>>>,

	/// Something that can create the inherent data providers.
	pub create_inherent_data_providers: CIDP,

	/// The signature keystore.
	pub keystore: Arc<dyn CryptoStore>,
	// pub _pp: PhantomData<PP>,
}

/// Params required to start the manual sealing authorship task.
pub struct InstantSealParams<B: BlockT, BI, E, C: ProvideRuntimeApi<B>, TP, SC, CIDP, P> {
	/// Block import instance for well. importing blocks.
	pub block_import: BI,

	/// The environment we are producing blocks for.
	pub env: E,

	/// Client instance
	pub client: Arc<C>,

	/// Shared reference to the transaction pool.
	pub pool: Arc<TP>,

	/// SelectChain strategy.
	pub select_chain: SC,

	/// Digest provider for inclusion in blocks.
	pub consensus_data_provider:
		Option<Box<dyn ConsensusDataProvider<B, Proof = P, Transaction = TransactionFor<C, B>>>>,

	/// Something that can create the inherent data providers.
	pub create_inherent_data_providers: CIDP,

	/// The signature keystore.
	pub keystore: Arc<dyn CryptoStore>,
	// pub _pp: PhantomData<PP>,
}

/// Creates the background authorship task for the manual seal engine.
pub async fn run_manual_seal<B, BI, CB, E, C, TP, SC, CS, CIDP, P, PP>(
	ManualSealParams {
		mut block_import,
		mut env,
		client,
		pool,
		mut commands_stream,
		select_chain,
		consensus_data_provider,
		create_inherent_data_providers,
		keystore,
	}: ManualSealParams<B, BI, E, C, TP, SC, CS, CIDP, P>,
) where
	B: BlockT + 'static,
	BI: BlockImport<B, Error = sp_consensus::Error, Transaction = sp_api::TransactionFor<C, B>>
		+ Send
		+ Sync
		+ 'static,
	C: HeaderBackend<B> + Finalizer<B, CB> + ProvideRuntimeApi<B> + 'static,
	C::Api: RaftApi<B, AuthorityId<PP>>,
	CB: ClientBackend<B> + 'static,
	E: Environment<B> + 'static,
	E::Proposer: Proposer<B, Proof = P, Transaction = TransactionFor<C, B>>,
	CS: Stream<Item = EngineCommand<<B as BlockT>::Hash, B>> + Unpin + 'static,
	SC: SelectChain<B> + 'static,
	TransactionFor<C, B>: 'static,
	TP: TransactionPool<Block = B>,
	CIDP: CreateInherentDataProviders<B, ()>,
	P: Send + Sync + 'static,
	PP: Pair + Send + Sync,
	PP::Public: AppPublic + Public + Member + Encode + Decode + Hash,
	PP::Signature: TryFrom<Vec<u8>> + Member + Encode + Decode + Hash + Debug,
{
	while let Some(command) = commands_stream.next().await {
		match command {
			EngineCommand::SealNewBlock { create_empty, finalize, parent_hash, sender } => {
				seal_block::<B, BI, SC, C, E, TP, CIDP, P, PP>(SealBlockParams {
					sender,
					parent_hash,
					finalize,
					create_empty,
					env: &mut env,
					select_chain: &select_chain,
					block_import: &mut block_import,
					consensus_data_provider: consensus_data_provider.as_deref(),
					pool: pool.clone(),
					client: client.clone(),
					create_inherent_data_providers: &create_inherent_data_providers,
					keystore: keystore.clone(),
				})
				.await;
			},
			EngineCommand::FinalizeBlock { hash, sender, justification } => {
				let justification = justification.map(|j| (MANUAL_SEAL_ENGINE_ID, j));
				finalize_block(FinalizeBlockParams {
					hash,
					sender,
					justification,
					finalizer: client.clone(),
					_phantom: PhantomData,
				})
				.await
			},
		}
	}
}

/// runs the background authorship task for the instant seal engine.
/// instant-seal creates a new block for every transaction imported into
/// the transaction pool.
pub async fn run_instant_seal<B, BI, CB, E, C, TP, SC, CIDP, P, PP>(
	InstantSealParams {
		block_import,
		env,
		client,
		pool,
		select_chain,
		consensus_data_provider,
		create_inherent_data_providers,
		keystore,
		// _pp,
	}: InstantSealParams<B, BI, E, C, TP, SC, CIDP, P>,
) where
	B: BlockT + 'static,
	BI: BlockImport<B, Error = sp_consensus::Error, Transaction = sp_api::TransactionFor<C, B>>
		+ Send
		+ Sync
		+ 'static,
	C: HeaderBackend<B> + Finalizer<B, CB> + ProvideRuntimeApi<B> + 'static,
	CB: ClientBackend<B> + 'static,
	E: Environment<B> + 'static,
	E::Proposer: Proposer<B, Proof = P, Transaction = TransactionFor<C, B>>,
	SC: SelectChain<B> + 'static,
	TransactionFor<C, B>: 'static,
	TP: TransactionPool<Block = B>,
	CIDP: CreateInherentDataProviders<B, ()>,
	P: Send + Sync + 'static,
	C::Api: RaftApi<B, AuthorityId<PP>>,
	PP: Pair + Send + Sync,
	PP::Public: AppPublic + Public + Member + Encode + Decode + Hash,
	PP::Signature: TryFrom<Vec<u8>> + Member + Encode + Decode + Hash + Debug,
{
	// instant-seal creates blocks as soon as transactions are imported
	// into the transaction pool.
	let commands_stream = pool.import_notification_stream().map(|_| EngineCommand::SealNewBlock {
		create_empty: false,
		finalize: false,
		parent_hash: None,
		sender: None,
	});

	run_manual_seal::<B, BI, CB, E, C, TP, SC, _, CIDP, P, PP>(ManualSealParams {
		block_import,
		env,
		client,
		pool,
		commands_stream,
		select_chain,
		consensus_data_provider,
		create_inherent_data_providers,
		keystore,
	})
	.await
}

pub async fn run_instant_seal_delayed<B, TP>(
	pool: Arc<TP>,
	mut sender: futures::channel::mpsc::Sender<EngineCommand<<B as BlockT>::Hash, B>>,
) where
	B: BlockT + 'static,
	TP: TransactionPool<Block = B>,
{
	while let Some(_command) = pool.import_notification_stream().next().await {
		loop {
			let res = sender
				.send(EngineCommand::SealNewBlock {
					create_empty: false,
					finalize: true,
					parent_hash: None,
					sender: None,
				})
				.await;
			match res {
				Ok(()) => break,
				Err(e) =>
					if e.is_full() {
						log::warn!(
							target: LOG_TARGET,
							"send command queue is full, will wait and retry"
						);
						tokio::time::sleep(Duration::from_secs(6)).await;
						continue
					} else {
						log::error!(target: LOG_TARGET, "failed to send to command queue: {e}");
						return
					},
			}
		}
		log::info!(target: LOG_TARGET, "seal delays until next batch");
		tokio::time::sleep(Duration::from_secs(6)).await;
		if pool.status().ready > 0 {
			log::warn!("playing a catch-up as there's a stuck transaction!");
			loop {
				let res = sender
					.send(EngineCommand::SealNewBlock {
						create_empty: false,
						finalize: false,
						parent_hash: None,
						sender: None,
					})
					.await;
				log::warn!("sent {:?}", res);
				match res {
					Ok(()) => break,
					Err(e) =>
						if e.is_full() {
							log::warn!(
								target: LOG_TARGET,
								"send command queue is full, will wait and retry"
							);
							tokio::time::sleep(Duration::from_secs(6)).await;
							continue
						} else {
							log::error!(target: LOG_TARGET, "failed to send to command queue: {e}");
							return
						},
				}
			}
		}
	}
}

/// Runs the background authorship task for the instant seal engine.
/// instant-seal creates a new block for every transaction imported into
/// the transaction pool.
///
/// This function will finalize the block immediately as well. If you don't
/// want this behavior use `run_instant_seal` instead.
pub async fn run_instant_seal_and_finalize<B, BI, CB, E, C, TP, SC, CIDP, P, PP>(
	InstantSealParams {
		block_import,
		env,
		client,
		pool,
		select_chain,
		consensus_data_provider,
		create_inherent_data_providers,
		keystore,
	}: InstantSealParams<B, BI, E, C, TP, SC, CIDP, P>,
) where
	B: BlockT + 'static,
	BI: BlockImport<B, Error = sp_consensus::Error, Transaction = sp_api::TransactionFor<C, B>>
		+ Send
		+ Sync
		+ 'static,
	C: HeaderBackend<B> + Finalizer<B, CB> + ProvideRuntimeApi<B> + 'static,
	CB: ClientBackend<B> + 'static,
	E: Environment<B> + 'static,
	E::Proposer: Proposer<B, Proof = P, Transaction = TransactionFor<C, B>>,
	SC: SelectChain<B> + 'static,
	TransactionFor<C, B>: 'static,
	TP: TransactionPool<Block = B>,
	CIDP: CreateInherentDataProviders<B, ()>,
	P: Send + Sync + 'static,
	C::Api: RaftApi<B, AuthorityId<PP>>,
	PP: Pair + Send + Sync,
	PP::Public: AppPublic + Public + Member + Encode + Decode + Hash,
	PP::Signature: TryFrom<Vec<u8>> + Member + Encode + Decode + Hash + Debug,
{
	// Creates and finalizes blocks as soon as transactions are imported
	// into the transaction pool.
	let commands_stream = pool.import_notification_stream().map(|_| EngineCommand::SealNewBlock {
		create_empty: false,
		finalize: true,
		parent_hash: None,
		sender: None,
	});

	run_manual_seal::<B, BI, CB, E, C, TP, SC, _, CIDP, P, PP>(ManualSealParams {
		block_import,
		env,
		client,
		pool,
		commands_stream,
		select_chain,
		consensus_data_provider,
		create_inherent_data_providers,
		keystore,
		// _pp: PhantomData,
	})
	.await
}
