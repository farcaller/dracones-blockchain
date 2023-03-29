//! Service and ServiceFactory implementation. Specialized wrapper over substrate service.

use crate::{
	client::RuntimeApiCollection,
	eth::{
		db_config_dir, new_frontier_partial, spawn_frontier_tasks, EthConfiguration,
		FrontierBackend, FrontierBlockImport, FrontierPartialComponents,
	},
};
use dracones_runtime::{self, opaque::Block, Hash, RuntimeApi, TransactionConverter};
use futures::channel::mpsc;
use sc_client_api::StateBackendFor;
use sc_consensus::BoxBlockImport;
pub use sc_executor::NativeElseWasmExecutor;
use sc_executor::NativeExecutionDispatch;
use sc_keystore::LocalKeystore;
use sc_service::{error::Error as ServiceError, ChainType, Configuration, TaskManager};
use sc_telemetry::{Telemetry, TelemetryWorker};
use sc_transaction_pool::FullPool;
use sp_api::ConstructRuntimeApi;
use sp_core::U256;
use sp_runtime::scale_info::Registry;
use std::sync::Arc;

// Our native executor instance.
pub struct ExecutorDispatch;

impl sc_executor::NativeExecutionDispatch for ExecutorDispatch {
	/// Only enable the benchmarking host functions when we actually want to benchmark.
	#[cfg(feature = "runtime-benchmarks")]
	type ExtendHostFunctions = frame_benchmarking::benchmarking::HostFunctions;
	/// Otherwise we only use the default Substrate host functions.
	#[cfg(not(feature = "runtime-benchmarks"))]
	type ExtendHostFunctions = ();

	fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
		dracones_runtime::api::dispatch(method, data)
	}

	fn native_version() -> sc_executor::NativeVersion {
		dracones_runtime::native_version()
	}
}

pub(crate) type FullClient =
	sc_service::TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<ExecutorDispatch>>;
type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;

pub fn new_partial(
	config: &Configuration,
) -> Result<
	sc_service::PartialComponents<
		FullClient,
		FullBackend,
		FullSelectChain,
		sc_consensus::DefaultImportQueue<Block, FullClient>,
		sc_transaction_pool::FullPool<Block, FullClient>,
		(Option<Telemetry>, Arc<FrontierBackend>),
	>,
	ServiceError,
> {
	if config.keystore_remote.is_some() {
		return Err(ServiceError::Other("Remote Keystores are not supported.".into()))
	}

	let telemetry = config
		.telemetry_endpoints
		.clone()
		.filter(|x| !x.is_empty())
		.map(|endpoints| -> Result<_, sc_telemetry::Error> {
			let worker = TelemetryWorker::new(16)?;
			let telemetry = worker.handle().new_telemetry(endpoints);
			Ok((worker, telemetry))
		})
		.transpose()?;

	let executor = NativeElseWasmExecutor::<ExecutorDispatch>::new(
		config.wasm_method,
		config.default_heap_pages,
		config.max_runtime_instances,
		config.runtime_cache_size,
	);

	let (client, backend, keystore_container, task_manager) =
		sc_service::new_full_parts::<Block, RuntimeApi, _>(
			config,
			telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
			executor,
		)?;
	let client = Arc::new(client);

	let telemetry = telemetry.map(|(worker, telemetry)| {
		task_manager.spawn_handle().spawn("telemetry", None, worker.run());
		telemetry
	});

	let select_chain = sc_consensus::LongestChain::new(backend.clone());

	let transaction_pool = sc_transaction_pool::BasicPool::new_full(
		config.transaction_pool.clone(),
		config.role.is_authority().into(),
		config.prometheus_registry(),
		task_manager.spawn_essential_handle(),
		client.clone(),
	);

	let frontier_backend =
		Arc::new(FrontierBackend::open(client.clone(), &config.database, &db_config_dir(config))?);

	let frontier_block_import =
		FrontierBlockImport::new(client.clone(), client.clone(), frontier_backend.clone());

	let import_queue = sc_consensus_raft_seal::import_queue(
		Box::new(frontier_block_import.clone()),
		&task_manager.spawn_essential_handle(),
		config.prometheus_registry(),
	);

	Ok(sc_service::PartialComponents {
		client,
		backend,
		task_manager,
		import_queue,
		keystore_container,
		select_chain,
		transaction_pool,
		other: (telemetry, frontier_backend),
	})
}

fn remote_keystore(_url: &String) -> Result<Arc<LocalKeystore>, &'static str> {
	// FIXME: here would the concrete keystore be built,
	//        must return a concrete type (NOT `LocalKeystore`) that
	//        implements `CryptoStore` and `SyncCryptoStore`
	Err("Remote Keystore not supported.")
}

/// Builds a new service for a full client.
pub fn new_full(
	mut config: Configuration,
	eth_config: EthConfiguration,
) -> Result<TaskManager, ServiceError> {
	let sc_service::PartialComponents {
		client,
		backend,
		mut task_manager,
		import_queue,
		mut keystore_container,
		select_chain,
		transaction_pool,
		other: (mut telemetry, frontier_backend),
	} = new_partial(&config)?;

	let FrontierPartialComponents { filter_pool, fee_history_cache, fee_history_cache_limit } =
		new_frontier_partial(&eth_config)?;

	if let Some(url) = &config.keystore_remote {
		match remote_keystore(url) {
			Ok(k) => keystore_container.set_remote_keystore(k),
			Err(e) =>
				return Err(ServiceError::Other(format!(
					"Error hooking up remote keystore for {}: {}",
					url, e
				))),
		};
	}

	let (network, system_rpc_tx, tx_handler_controller, network_starter) =
		sc_service::build_network(sc_service::BuildNetworkParams {
			config: &config,
			client: client.clone(),
			transaction_pool: transaction_pool.clone(),
			spawn_handle: task_manager.spawn_handle(),
			import_queue,
			block_announce_validator_builder: None,
			warp_sync_params: None,
		})?;

	if config.offchain_worker.enabled {
		sc_service::build_offchain_workers(
			&config,
			task_manager.spawn_handle(),
			client.clone(),
			network.clone(),
		);
	}

	let role = config.role.clone();
	let prometheus_registry = config.prometheus_registry().cloned();

	if config.chain_spec.chain_type() == ChainType::Development {
		let store = keystore_container.sync_keystore();
		sp_keystore::SyncCryptoStore::sr25519_generate_new(
			store.as_ref(),
			sp_consensus_raft::RAFT_KEY_TYPE,
			Some("//Raft"),
		)
		.expect("failed to inject a raft sealing key");
	}

	config.rpc_id_provider = Some(Box::new(fc_rpc::EthereumSubIdProvider));
	let overrides = crate::rpc::overrides_handle(client.clone());
	let eth_rpc_params = crate::rpc::EthDeps {
		client: client.clone(),
		pool: transaction_pool.clone(),
		graph: transaction_pool.pool().clone(),
		converter: Some(TransactionConverter),
		is_authority: config.role.is_authority(),
		enable_dev_signer: eth_config.enable_dev_signer,
		network: network.clone(),
		frontier_backend: frontier_backend.clone(),
		overrides: overrides.clone(),
		block_data_cache: Arc::new(fc_rpc::EthBlockDataCacheTask::new(
			task_manager.spawn_handle(),
			overrides.clone(),
			eth_config.eth_log_block_cache,
			eth_config.eth_statuses_cache,
			prometheus_registry.clone(),
		)),
		filter_pool: filter_pool.clone(),
		max_past_logs: eth_config.max_past_logs,
		fee_history_cache: fee_history_cache.clone(),
		fee_history_cache_limit,
		execute_gas_limit_multiplier: eth_config.execute_gas_limit_multiplier,
	};

	let rpc_extensions_builder = {
		let client = client.clone();
		let pool = transaction_pool.clone();

		Box::new(move |deny_unsafe, subscription_task_executor| {
			let deps = crate::rpc::FullDeps {
				client: client.clone(),
				pool: pool.clone(),
				deny_unsafe,
				eth: eth_rpc_params.clone(),
			};
			crate::rpc::create_full(deps, subscription_task_executor).map_err(Into::into)
		})
	};

	let _rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
		network: network.clone(),
		client: client.clone(),
		keystore: keystore_container.sync_keystore(),
		task_manager: &mut task_manager,
		transaction_pool: transaction_pool.clone(),
		rpc_builder: rpc_extensions_builder,
		backend: backend.clone(),
		system_rpc_tx,
		tx_handler_controller,
		config,
		telemetry: telemetry.as_mut(),
	})?;

	spawn_frontier_tasks(
		&task_manager,
		client.clone(),
		backend,
		frontier_backend,
		filter_pool,
		overrides,
		fee_history_cache,
		fee_history_cache_limit,
	);

	if role.is_authority() {
		let proposer_factory = sc_basic_authorship::ProposerFactory::new(
			task_manager.spawn_handle(),
			client.clone(),
			transaction_pool.clone(),
			prometheus_registry.as_ref(),
			telemetry.as_ref().map(|x| x.handle()),
		);

		let (commands_stream_tx, commands_stream_rx) = futures::channel::mpsc::channel(100);

		let seal_queue_future = sc_consensus_raft_seal::run_instant_seal_delayed(
			transaction_pool.clone(),
			commands_stream_tx,
		);

		task_manager.spawn_essential_handle().spawn_blocking(
			"instant-seal-queue",
			None,
			seal_queue_future,
		);

		let target_gas_price = eth_config.target_gas_price;
		let create_inherent_data_providers = move |_, ()| async move {
			let timestamp = sp_timestamp::InherentDataProvider::from_system_time();
			let dynamic_fee = fp_dynamic_fee::InherentDataProvider(U256::from(target_gas_price));
			Ok((timestamp, dynamic_fee))
		};

		let params = sc_consensus_raft_seal::ManualSealParams {
			block_import: client.clone(),
			env: proposer_factory,
			client,
			pool: transaction_pool,
			select_chain,
			consensus_data_provider: None,
			create_inherent_data_providers,
			keystore: keystore_container.keystore(),
			commands_stream: commands_stream_rx,
		};

		let authorship_future = sc_consensus_raft_seal::run_manual_seal::<
			_,
			_,
			_,
			_,
			_,
			_,
			_,
			_,
			_,
			_,
			sp_consensus_raft::sr25519::app_sr25519::Pair,
		>(params);

		task_manager.spawn_essential_handle().spawn_blocking(
			"instant-seal",
			None,
			authorship_future,
		);
	}

	network_starter.start_network();
	Ok(task_manager)
}

// fn run_manual_seal_authorship<RuntimeApi, Executor>(
// 	eth_config: &EthConfiguration,
// 	client: Arc<FullClient>,
// 	transaction_pool: Arc<FullPool<FullClient>>,
// 	select_chain: FullSelectChain,
// 	block_import: BoxBlockImport<FullClient>,
// 	task_manager: &TaskManager,
// 	prometheus_registry: Option<&Registry>,
// 	telemetry: Option<&Telemetry>,
// 	commands_stream: mpsc::Receiver<sc_consensus_raft_seal::rpc::EngineCommand<Hash>>,
// ) -> Result<(), ServiceError>
// where
// 	RuntimeApi: ConstructRuntimeApi<Block, FullClient>,
// 	RuntimeApi: Send + Sync + 'static,
// 	RuntimeApi::RuntimeApi:
// 		RuntimeApiCollection<StateBackend = StateBackendFor<FullBackend, Block>>,
// 	Executor: NativeExecutionDispatch + 'static,
// {
// 	let proposer_factory = sc_basic_authorship::ProposerFactory::new(
// 		task_manager.spawn_handle(),
// 		client.clone(),
// 		transaction_pool.clone(),
// 		prometheus_registry,
// 		telemetry.as_ref().map(|x| x.handle()),
// 	);

// 	thread_local!(static TIMESTAMP: RefCell<u64> = RefCell::new(0));

// 	/// Provide a mock duration starting at 0 in millisecond for timestamp inherent.
// 	/// Each call will increment timestamp by slot_duration making Aura think time has passed.
// 	struct MockTimestampInherentDataProvider;

// 	#[async_trait::async_trait]
// 	impl sp_inherents::InherentDataProvider for MockTimestampInherentDataProvider {
// 		async fn provide_inherent_data(
// 			&self,
// 			inherent_data: &mut sp_inherents::InherentData,
// 		) -> Result<(), sp_inherents::Error> {
// 			TIMESTAMP.with(|x| {
// 				*x.borrow_mut() += frontier_template_runtime::SLOT_DURATION;
// 				inherent_data.put_data(sp_timestamp::INHERENT_IDENTIFIER, &*x.borrow())
// 			})
// 		}

// 		async fn try_handle_error(
// 			&self,
// 			_identifier: &sp_inherents::InherentIdentifier,
// 			_error: &[u8],
// 		) -> Option<Result<(), sp_inherents::Error>> {
// 			// The pallet never reports error.
// 			None
// 		}
// 	}

// 	let target_gas_price = eth_config.target_gas_price;
// 	let create_inherent_data_providers = move |_, ()| async move {
// 		let timestamp = MockTimestampInherentDataProvider;
// 		let dynamic_fee = fp_dynamic_fee::InherentDataProvider(U256::from(target_gas_price));
// 		Ok((timestamp, dynamic_fee))
// 	};

// 	let manual_seal = match sealing {
// 		Sealing::Manual => future::Either::Left(sc_consensus_manual_seal::run_manual_seal(
// 			sc_consensus_manual_seal::ManualSealParams {
// 				block_import,
// 				env: proposer_factory,
// 				client,
// 				pool: transaction_pool,
// 				commands_stream,
// 				select_chain,
// 				consensus_data_provider: None,
// 				create_inherent_data_providers,
// 			},
// 		)),
// 		Sealing::Instant => future::Either::Right(sc_consensus_manual_seal::run_instant_seal(
// 			sc_consensus_manual_seal::InstantSealParams {
// 				block_import,
// 				env: proposer_factory,
// 				client,
// 				pool: transaction_pool,
// 				select_chain,
// 				consensus_data_provider: None,
// 				create_inherent_data_providers,
// 			},
// 		)),
// 	};

// 	// we spawn the future on a background thread managed by service.
// 	task_manager
// 		.spawn_essential_handle()
// 		.spawn_blocking("manual-seal", None, manual_seal);
// 	Ok(())
// }
