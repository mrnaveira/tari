// Copyright 2019. The Tari Project
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crate::support::{
    data::get_temp_sqlite_database_connection,
    rpc::{BaseNodeWalletRpcMockService, BaseNodeWalletRpcMockState},
    utils::{make_input, make_input_with_features, TestParams},
};
use futures::{FutureExt, StreamExt};
use rand::{rngs::OsRng, RngCore};
use std::{sync::Arc, thread, time::Duration};
use tari_comms::{
    peer_manager::{NodeIdentity, PeerFeatures},
    protocol::rpc::{mock::MockRpcServer, NamedProtocolService, RpcStatus},
    test_utils::{
        mocks::{create_connectivity_mock, ConnectivityManagerMockState},
        node_identity::build_node_identity,
    },
    types::CommsSecretKey,
    Substream,
};
use tari_core::{
    base_node::rpc::BaseNodeWalletRpcServer,
    consensus::ConsensusConstantsBuilder,
    transactions::{
        fee::Fee,
        helpers::{create_unblinded_output, TestParams as TestParamsHelpers},
        tari_amount::{uT, MicroTari},
        transaction::{KernelFeatures, OutputFeatures, Transaction},
        transaction_protocol::{
            recipient::RecipientState,
            sender::TransactionSenderMessage,
            single_receiver::SingleReceiverTransactionProtocol,
        },
        types::{CryptoFactories, PrivateKey, PublicKey},
        SenderTransactionProtocol,
    },
};
use tari_crypto::{
    hash::blake2::Blake256,
    inputs,
    keys::{PublicKey as PublicKeyTrait, SecretKey},
    script,
    script::TariScript,
};
use tari_p2p::Network;
use tari_service_framework::reply_channel;
use tari_shutdown::Shutdown;
use tari_wallet::{
    base_node_service::{handle::BaseNodeServiceHandle, mock_base_node_service::MockBaseNodeService},
    output_manager_service::{
        config::OutputManagerServiceConfig,
        error::{OutputManagerError, OutputManagerStorageError},
        handle::{OutputManagerEvent, OutputManagerHandle},
        service::OutputManagerService,
        storage::{
            database::{DbKey, DbKeyValuePair, DbValue, OutputManagerBackend, OutputManagerDatabase, WriteOperation},
            models::DbUnblindedOutput,
            sqlite_db::OutputManagerSqliteDatabase,
        },
        TxId,
        TxoValidationType,
    },
    transaction_service::handle::TransactionServiceHandle,
    types::ValidationRetryStrategy,
};

use tari_wallet::output_manager_service::storage::models::OutputStatus;
use tokio::{
    runtime::Runtime,
    sync::{broadcast, broadcast::channel},
    time::delay_for,
};

#[allow(clippy::type_complexity)]
pub fn setup_output_manager_service<T: OutputManagerBackend + 'static>(
    runtime: &mut Runtime,
    backend: T,
    with_connection: bool,
) -> (
    OutputManagerHandle,
    Shutdown,
    TransactionServiceHandle,
    MockRpcServer<BaseNodeWalletRpcServer<BaseNodeWalletRpcMockService>, Substream>,
    Arc<NodeIdentity>,
    BaseNodeWalletRpcMockState,
    ConnectivityManagerMockState,
) {
    let shutdown = Shutdown::new();
    let factories = CryptoFactories::default();

    let (oms_request_sender, oms_request_receiver) = reply_channel::unbounded();
    let (oms_event_publisher, _) = broadcast::channel(200);

    let (ts_request_sender, _ts_request_receiver) = reply_channel::unbounded();
    let (event_publisher, _) = channel(100);
    let ts_handle = TransactionServiceHandle::new(ts_request_sender, event_publisher);

    let constants = ConsensusConstantsBuilder::new(Network::Weatherwax).build();

    let (sender, receiver_bns) = reply_channel::unbounded();
    let (event_publisher_bns, _) = broadcast::channel(100);

    let basenode_service_handle = BaseNodeServiceHandle::new(sender, event_publisher_bns);
    let mut mock_base_node_service = MockBaseNodeService::new(receiver_bns, shutdown.to_signal());
    mock_base_node_service.set_default_base_node_state();
    runtime.spawn(mock_base_node_service.run());

    let (connectivity_manager, connectivity_mock) = create_connectivity_mock();
    let connectivity_mock_state = connectivity_mock.get_shared_state();
    runtime.spawn(connectivity_mock.run());

    let service = BaseNodeWalletRpcMockService::new();
    let rpc_service_state = service.get_state();

    let server = BaseNodeWalletRpcServer::new(service);
    let protocol_name = server.as_protocol_name();
    let server_node_identity = build_node_identity(PeerFeatures::COMMUNICATION_NODE);

    let mut mock_server = runtime
        .handle()
        .enter(|| MockRpcServer::new(server, server_node_identity.clone()));

    runtime.handle().enter(|| mock_server.serve());

    if with_connection {
        let connection = runtime.block_on(async {
            mock_server
                .create_connection(server_node_identity.to_peer(), protocol_name.into())
                .await
        });
        runtime.block_on(connectivity_mock_state.add_active_connection(connection));
    }
    let output_manager_service = runtime
        .block_on(OutputManagerService::new(
            OutputManagerServiceConfig {
                base_node_query_timeout: Duration::from_secs(10),
                max_utxo_query_size: 2,
                peer_dial_retry_timeout: Duration::from_secs(5),
                ..Default::default()
            },
            ts_handle.clone(),
            oms_request_receiver,
            OutputManagerDatabase::new(backend),
            oms_event_publisher.clone(),
            factories,
            constants,
            shutdown.to_signal(),
            basenode_service_handle,
            connectivity_manager,
            CommsSecretKey::default(),
        ))
        .unwrap();
    let output_manager_service_handle = OutputManagerHandle::new(oms_request_sender, oms_event_publisher);

    runtime.spawn(async move { output_manager_service.start().await.unwrap() });

    (
        output_manager_service_handle,
        shutdown,
        ts_handle,
        mock_server,
        server_node_identity,
        rpc_service_state,
        connectivity_mock_state,
    )
}

async fn complete_transaction(mut stp: SenderTransactionProtocol, mut oms: OutputManagerHandle) -> Transaction {
    let factories = CryptoFactories::default();

    let sender_tx_id = stp.get_tx_id().unwrap();
    // Is there change? Unlikely not to be but the random amounts MIGHT produce a no change output situation
    if stp.get_amount_to_self().unwrap() > MicroTari::from(0) {
        let pt = oms.get_pending_transactions().await.unwrap();
        assert_eq!(pt.len(), 1);
        assert_eq!(
            pt.get(&sender_tx_id).unwrap().outputs_to_be_received[0]
                .unblinded_output
                .value,
            stp.get_amount_to_self().unwrap()
        );
    }
    let msg = stp.build_single_round_message().unwrap();
    let b = TestParams::new(&mut OsRng);
    let recv_info = SingleReceiverTransactionProtocol::create(
        &msg,
        b.nonce,
        b.spend_key,
        OutputFeatures::default(),
        &factories,
        None,
    )
    .unwrap();
    stp.add_single_recipient_info(recv_info, &factories.range_proof)
        .unwrap();
    stp.finalize(KernelFeatures::empty(), &factories).unwrap();
    stp.get_transaction().unwrap().clone()
}

pub fn setup_oms_with_bn_state<T: OutputManagerBackend + 'static>(
    runtime: &mut Runtime,
    backend: T,
    height: Option<u64>,
) -> (
    OutputManagerHandle,
    Shutdown,
    TransactionServiceHandle,
    BaseNodeServiceHandle,
) {
    let shutdown = Shutdown::new();
    let factories = CryptoFactories::default();

    let (oms_request_sender, oms_request_receiver) = reply_channel::unbounded();
    let (oms_event_publisher, _) = broadcast::channel(200);

    let (ts_request_sender, _ts_request_receiver) = reply_channel::unbounded();
    let (event_publisher, _) = channel(100);
    let ts_handle = TransactionServiceHandle::new(ts_request_sender, event_publisher);

    let constants = ConsensusConstantsBuilder::new(Network::Weatherwax).build();

    let (sender, receiver_bns) = reply_channel::unbounded();
    let (event_publisher_bns, _) = broadcast::channel(100);

    let base_node_service_handle = BaseNodeServiceHandle::new(sender, event_publisher_bns);
    let mut mock_base_node_service = MockBaseNodeService::new(receiver_bns, shutdown.to_signal());
    mock_base_node_service.set_base_node_state(height);
    runtime.spawn(mock_base_node_service.run());

    let (connectivity_manager, connectivity_mock) = create_connectivity_mock();
    let _connectivity_mock_state = connectivity_mock.get_shared_state();
    runtime.spawn(connectivity_mock.run());

    let output_manager_service = runtime
        .block_on(OutputManagerService::new(
            OutputManagerServiceConfig {
                base_node_query_timeout: Duration::from_secs(10),
                max_utxo_query_size: 2,
                peer_dial_retry_timeout: Duration::from_secs(5),
                ..Default::default()
            },
            ts_handle.clone(),
            oms_request_receiver,
            OutputManagerDatabase::new(backend),
            oms_event_publisher.clone(),
            factories,
            constants,
            shutdown.to_signal(),
            base_node_service_handle.clone(),
            connectivity_manager,
            CommsSecretKey::default(),
        ))
        .unwrap();
    let output_manager_service_handle = OutputManagerHandle::new(oms_request_sender, oms_event_publisher);

    runtime.spawn(async move { output_manager_service.start().await.unwrap() });

    (
        output_manager_service_handle,
        shutdown,
        ts_handle,
        base_node_service_handle,
    )
}

fn generate_sender_transaction_message(amount: MicroTari) -> (TxId, TransactionSenderMessage) {
    let factories = CryptoFactories::default();

    let alice = TestParams::new(&mut OsRng);

    let (utxo, input) = make_input(&mut OsRng, 2 * amount, &factories.commitment);
    let mut builder = SenderTransactionProtocol::builder(1);
    let script_private_key = PrivateKey::random(&mut OsRng);
    builder
        .with_lock_height(0)
        .with_fee_per_gram(MicroTari(20))
        .with_offset(alice.offset.clone())
        .with_private_nonce(alice.nonce.clone())
        .with_change_secret(alice.change_spend_key)
        .with_input(utxo, input)
        .with_amount(0, amount)
        .with_recipient_data(
            0,
            script!(Nop),
            PrivateKey::random(&mut OsRng),
            OutputFeatures::default(),
            PrivateKey::random(&mut OsRng),
        )
        .with_change_script(
            script!(Nop),
            inputs!(PublicKey::from_secret_key(&script_private_key)),
            script_private_key,
        );

    let mut stp = builder.build::<Blake256>(&factories).unwrap();
    let tx_id = stp.get_tx_id().unwrap();
    (
        tx_id,
        TransactionSenderMessage::new_single_round_message(stp.build_single_round_message().unwrap()),
    )
}

#[test]
fn fee_estimate() {
    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let backend = OutputManagerSqliteDatabase::new(connection, None);

    let factories = CryptoFactories::default();
    let mut runtime = Runtime::new().unwrap();
    let (mut oms, _shutdown, _, _, _, _, _) = setup_output_manager_service(&mut runtime, backend, true);

    let (_, uo) = make_input(&mut OsRng.clone(), MicroTari::from(3000), &factories.commitment);
    runtime.block_on(oms.add_output(uo)).unwrap();

    // minimum fee
    let fee_per_gram = MicroTari::from(1);
    let fee = runtime
        .block_on(oms.fee_estimate(MicroTari::from(100), fee_per_gram, 1, 1))
        .unwrap();
    assert_eq!(fee, MicroTari::from(100));

    let fee_per_gram = MicroTari::from(25);
    for outputs in 1..5 {
        let fee = runtime
            .block_on(oms.fee_estimate(MicroTari::from(100), fee_per_gram, 1, outputs))
            .unwrap();
        assert_eq!(fee, Fee::calculate(fee_per_gram, 1, 1, outputs as usize));
    }

    // not enough funds
    let err = runtime
        .block_on(oms.fee_estimate(MicroTari::from(2750), fee_per_gram, 1, 1))
        .unwrap_err();
    assert!(matches!(err, OutputManagerError::NotEnoughFunds));
}

#[allow(clippy::identity_op)]
#[test]
fn test_utxo_selection_no_chain_metadata() {
    let factories = CryptoFactories::default();
    let mut runtime = Runtime::new().unwrap();
    let (connection, _tempdir) = get_temp_sqlite_database_connection();

    // no chain metadata
    let (mut oms, _shutdown, _, _) =
        setup_oms_with_bn_state(&mut runtime, OutputManagerSqliteDatabase::new(connection, None), None);

    // no utxos - not enough funds
    let amount = MicroTari::from(1000);
    let fee_per_gram = MicroTari::from(10);
    let err = runtime
        .block_on(oms.prepare_transaction_to_send(
            OsRng.next_u64(),
            amount,
            fee_per_gram,
            None,
            "".to_string(),
            script!(Nop),
        ))
        .unwrap_err();
    assert!(matches!(err, OutputManagerError::NotEnoughFunds));

    // create 10 utxos with maturity at heights from 1 to 10
    for i in 1..=10 {
        let (_, uo) = make_input_with_features(
            &mut OsRng.clone(),
            i * amount,
            &factories.commitment,
            Some(OutputFeatures::with_maturity(i)),
        );
        runtime.block_on(oms.add_output(uo.clone())).unwrap();
    }

    // but we have no chain state so the lowest maturity should be used
    let stp = runtime
        .block_on(oms.prepare_transaction_to_send(
            OsRng.next_u64(),
            amount,
            fee_per_gram,
            None,
            "".to_string(),
            script!(Nop),
        ))
        .unwrap();
    assert!(stp.get_tx_id().is_ok());

    // test that lowest 2 maturities were encumbered
    let utxos = runtime.block_on(oms.get_unspent_outputs()).unwrap();
    assert_eq!(utxos.len(), 8);
    for (index, utxo) in utxos.iter().enumerate() {
        let i = index as u64 + 3;
        assert_eq!(utxo.features.maturity, i);
        assert_eq!(utxo.value, i * amount);
    }

    // test that we can get a fee estimate with no chain metadata
    let fee = runtime.block_on(oms.fee_estimate(amount, fee_per_gram, 1, 2)).unwrap();
    assert_eq!(fee, MicroTari::from(300));

    // test if a fee estimate would be possible with pending funds included
    // at this point 52000 uT is still spendable, with pending change incoming of 1690 uT
    // so instead of returning "not enough funds", return "funds pending"
    let spendable_amount = (3..=10).sum::<u64>() * amount;
    let err = runtime
        .block_on(oms.fee_estimate(spendable_amount, fee_per_gram, 1, 2))
        .unwrap_err();
    assert!(matches!(err, OutputManagerError::FundsPending));

    // test not enough funds
    let broke_amount = spendable_amount + MicroTari::from(2000);
    let err = runtime
        .block_on(oms.fee_estimate(broke_amount, fee_per_gram, 1, 2))
        .unwrap_err();
    assert!(matches!(err, OutputManagerError::NotEnoughFunds));

    // coin split uses the "Largest" selection strategy
    let (_, _, fee, utxos_total_value) = runtime
        .block_on(oms.create_coin_split(amount, 5, fee_per_gram, None))
        .unwrap();
    assert_eq!(fee, MicroTari::from(820));
    assert_eq!(utxos_total_value, MicroTari::from(10_000));

    // test that largest utxo was encumbered
    let utxos = runtime.block_on(oms.get_unspent_outputs()).unwrap();
    assert_eq!(utxos.len(), 7);
    for (index, utxo) in utxos.iter().enumerate() {
        let i = index as u64 + 3;
        assert_eq!(utxo.features.maturity, i);
        assert_eq!(utxo.value, i * amount);
    }
}

#[allow(clippy::identity_op)]
#[test]
fn test_utxo_selection_with_chain_metadata() {
    let factories = CryptoFactories::default();
    let mut runtime = Runtime::new().unwrap();
    let (connection, _tempdir) = get_temp_sqlite_database_connection();

    // setup with chain metadata at a height of 6
    let (mut oms, _shutdown, _, _) = setup_oms_with_bn_state(
        &mut runtime,
        OutputManagerSqliteDatabase::new(connection, None),
        Some(6),
    );

    // no utxos - not enough funds
    let amount = MicroTari::from(1000);
    let fee_per_gram = MicroTari::from(10);
    let err = runtime
        .block_on(oms.prepare_transaction_to_send(
            OsRng.next_u64(),
            amount,
            fee_per_gram,
            None,
            "".to_string(),
            script!(Nop),
        ))
        .unwrap_err();
    assert!(matches!(err, OutputManagerError::NotEnoughFunds));

    // create 10 utxos with maturity at heights from 1 to 10
    for i in 1..=10 {
        let (_, uo) = make_input_with_features(
            &mut OsRng.clone(),
            i * amount,
            &factories.commitment,
            Some(OutputFeatures::with_maturity(i)),
        );
        runtime.block_on(oms.add_output(uo.clone())).unwrap();
    }

    let utxos = runtime.block_on(oms.get_unspent_outputs()).unwrap();
    assert_eq!(utxos.len(), 10);

    // test fee estimates
    let fee = runtime.block_on(oms.fee_estimate(amount, fee_per_gram, 1, 2)).unwrap();
    assert_eq!(fee, MicroTari::from(310));

    // test fee estimates are maturity aware
    // even though we have utxos for the fee, they can't be spent because they are not mature yet
    let spendable_amount = (1..=6).sum::<u64>() * amount;
    let err = runtime
        .block_on(oms.fee_estimate(spendable_amount, fee_per_gram, 1, 2))
        .unwrap_err();
    assert!(matches!(err, OutputManagerError::NotEnoughFunds));

    // test coin split is maturity aware
    let (_, _, fee, utxos_total_value) = runtime
        .block_on(oms.create_coin_split(amount, 5, fee_per_gram, None))
        .unwrap();
    assert_eq!(utxos_total_value, MicroTari::from(6_000));
    assert_eq!(fee, MicroTari::from(820));

    // test that largest spendable utxo was encumbered
    let utxos = runtime.block_on(oms.get_unspent_outputs()).unwrap();
    assert_eq!(utxos.len(), 9);
    let found = utxos.iter().any(|u| u.value == 6 * amount);
    assert!(!found, "An unspendable utxo was selected");

    // test transactions
    let stp = runtime
        .block_on(oms.prepare_transaction_to_send(
            OsRng.next_u64(),
            amount,
            fee_per_gram,
            None,
            "".to_string(),
            script!(Nop),
        ))
        .unwrap();
    assert!(stp.get_tx_id().is_ok());

    // test that utxos with the lowest 2 maturities were encumbered
    let utxos = runtime.block_on(oms.get_unspent_outputs()).unwrap();
    assert_eq!(utxos.len(), 7);
    for utxo in utxos.iter() {
        assert_ne!(utxo.features.maturity, 1);
        assert_ne!(utxo.value, amount);
        assert_ne!(utxo.features.maturity, 2);
        assert_ne!(utxo.value, 2 * amount);
    }

    // when the amount is greater than the largest utxo, then "Largest" selection strategy is used
    let stp = runtime
        .block_on(oms.prepare_transaction_to_send(
            OsRng.next_u64(),
            6 * amount,
            fee_per_gram,
            None,
            "".to_string(),
            script!(Nop),
        ))
        .unwrap();
    assert!(stp.get_tx_id().is_ok());

    // test that utxos with the highest spendable 2 maturities were encumbered
    let utxos = runtime.block_on(oms.get_unspent_outputs()).unwrap();
    assert_eq!(utxos.len(), 5);
    for utxo in utxos.iter() {
        assert_ne!(utxo.features.maturity, 4);
        assert_ne!(utxo.value, 4 * amount);
        assert_ne!(utxo.features.maturity, 5);
        assert_ne!(utxo.value, 5 * amount);
    }
}

#[test]
fn sending_transaction_and_confirmation() {
    let factories = CryptoFactories::default();
    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let backend = OutputManagerSqliteDatabase::new(connection, None);
    let mut runtime = Runtime::new().unwrap();

    let (mut oms, _shutdown, _, _, _, _, _) = setup_output_manager_service(&mut runtime, backend.clone(), true);

    let (_ti, uo) = make_input(
        &mut OsRng.clone(),
        MicroTari::from(100 + OsRng.next_u64() % 1000),
        &factories.commitment,
    );
    runtime.block_on(oms.add_output(uo.clone())).unwrap();
    match runtime.block_on(oms.add_output(uo)) {
        Err(OutputManagerError::OutputManagerStorageError(OutputManagerStorageError::DuplicateOutput)) => {},
        _ => panic!("Incorrect error message"),
    };
    let num_outputs = 20;
    for _i in 0..num_outputs {
        let (_ti, uo) = make_input(
            &mut OsRng.clone(),
            MicroTari::from(100 + OsRng.next_u64() % 1000),
            &factories.commitment,
        );
        runtime.block_on(oms.add_output(uo)).unwrap();
    }

    let stp = runtime
        .block_on(oms.prepare_transaction_to_send(
            OsRng.next_u64(),
            MicroTari::from(1000),
            MicroTari::from(20),
            None,
            "".to_string(),
            script!(Nop),
        ))
        .unwrap();

    let sender_tx_id = stp.get_tx_id().unwrap();

    let tx = runtime.block_on(complete_transaction(stp, oms.clone()));

    let rewind_public_keys = runtime.block_on(oms.get_rewind_public_keys()).unwrap();

    // 1 of the 2 outputs should be rewindable, there should be 2 outputs due to change but if we get unlucky enough
    // that there is no change we will skip this aspect of the test
    if tx.body.outputs().len() > 1 {
        let mut num_rewound = 0;

        let output = tx.body.outputs()[0].clone();
        if output
            .rewind_range_proof_value_only(
                &factories.range_proof,
                &rewind_public_keys.rewind_public_key,
                &rewind_public_keys.rewind_blinding_public_key,
            )
            .is_ok()
        {
            num_rewound += 1;
        }

        let output = tx.body.outputs()[1].clone();
        if output
            .rewind_range_proof_value_only(
                &factories.range_proof,
                &rewind_public_keys.rewind_public_key,
                &rewind_public_keys.rewind_blinding_public_key,
            )
            .is_ok()
        {
            num_rewound += 1;
        }
        assert_eq!(num_rewound, 1, "Should only be 1 rewindable output");
    }

    runtime
        .block_on(oms.confirm_transaction(sender_tx_id, tx.body.inputs().clone(), tx.body.outputs().clone()))
        .unwrap();

    assert_eq!(
        runtime.block_on(oms.get_pending_transactions()).unwrap().len(),
        0,
        "Should have no pending tx"
    );
    assert_eq!(
        runtime.block_on(oms.get_spent_outputs()).unwrap().len(),
        tx.body.inputs().len(),
        "# Outputs should equal number of sent inputs"
    );
    assert_eq!(
        runtime.block_on(oms.get_unspent_outputs()).unwrap().len(),
        num_outputs + 1 - runtime.block_on(oms.get_spent_outputs()).unwrap().len() + tx.body.outputs().len() - 1,
        "Unspent outputs"
    );

    if let DbValue::KeyManagerState(km) = backend.fetch(&DbKey::KeyManagerState).unwrap().unwrap() {
        // if we dont have change, we did not move the index forward
        if tx.body.outputs().len() > 1 {
            assert_eq!(km.primary_key_index, 1);
        } else {
            assert_eq!(km.primary_key_index, 0);
        }
    } else {
        panic!("No Key Manager set");
    }
}

#[test]
fn send_not_enough_funds() {
    let factories = CryptoFactories::default();

    let mut runtime = Runtime::new().unwrap();

    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let backend = OutputManagerSqliteDatabase::new(connection, None);

    let (mut oms, _shutdown, _, _, _, _, _) = setup_output_manager_service(&mut runtime, backend, true);
    let num_outputs = 20;
    for _i in 0..num_outputs {
        let (_ti, uo) = make_input(
            &mut OsRng.clone(),
            MicroTari::from(100 + OsRng.next_u64() % 1000),
            &factories.commitment,
        );
        runtime.block_on(oms.add_output(uo)).unwrap();
    }

    match runtime.block_on(oms.prepare_transaction_to_send(
        OsRng.next_u64(),
        MicroTari::from(num_outputs * 2000),
        MicroTari::from(20),
        None,
        "".to_string(),
        script!(Nop),
    )) {
        Err(OutputManagerError::NotEnoughFunds) => {},
        _ => panic!(),
    }
}

#[test]
fn send_no_change() {
    let factories = CryptoFactories::default();

    let mut runtime = Runtime::new().unwrap();

    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let backend = OutputManagerSqliteDatabase::new(connection, None);

    let (mut oms, _shutdown, _, _, _, _, _) = setup_output_manager_service(&mut runtime, backend, true);

    let fee_per_gram = MicroTari::from(20);
    let fee_without_change = Fee::calculate(fee_per_gram, 1, 2, 1);
    let value1 = 500;
    runtime
        .block_on(oms.add_output(create_unblinded_output(
            script!(Nop),
            OutputFeatures::default(),
            TestParamsHelpers::new(),
            MicroTari::from(value1),
        )))
        .unwrap();
    let value2 = 800;
    runtime
        .block_on(oms.add_output(create_unblinded_output(
            script!(Nop),
            OutputFeatures::default(),
            TestParamsHelpers::new(),
            MicroTari::from(value2),
        )))
        .unwrap();

    let mut stp = runtime
        .block_on(oms.prepare_transaction_to_send(
            OsRng.next_u64(),
            MicroTari::from(value1 + value2) - fee_without_change,
            fee_per_gram,
            None,
            "".to_string(),
            script!(Nop),
        ))
        .unwrap();

    let sender_tx_id = stp.get_tx_id().unwrap();
    assert_eq!(stp.get_amount_to_self().unwrap(), MicroTari::from(0));
    assert_eq!(runtime.block_on(oms.get_pending_transactions()).unwrap().len(), 1);

    let msg = stp.build_single_round_message().unwrap();

    let b = TestParams::new(&mut OsRng);

    let recv_info = SingleReceiverTransactionProtocol::create(
        &msg,
        b.nonce,
        b.spend_key,
        OutputFeatures::default(),
        &factories,
        None,
    )
    .unwrap();

    stp.add_single_recipient_info(recv_info, &factories.range_proof)
        .unwrap();

    stp.finalize(KernelFeatures::empty(), &factories).unwrap();

    let tx = stp.get_transaction().unwrap();

    runtime
        .block_on(oms.confirm_transaction(sender_tx_id, tx.body.inputs().clone(), tx.body.outputs().clone()))
        .unwrap();

    assert_eq!(runtime.block_on(oms.get_pending_transactions()).unwrap().len(), 0);
    assert_eq!(
        runtime.block_on(oms.get_spent_outputs()).unwrap().len(),
        tx.body.inputs().len()
    );
    assert_eq!(runtime.block_on(oms.get_unspent_outputs()).unwrap().len(), 0);
}

#[test]
fn send_not_enough_for_change() {
    let mut runtime = Runtime::new().unwrap();

    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let backend = OutputManagerSqliteDatabase::new(connection, None);

    let (mut oms, _shutdown, _, _, _, _, _) = setup_output_manager_service(&mut runtime, backend, true);

    let fee_per_gram = MicroTari::from(20);
    let fee_without_change = Fee::calculate(fee_per_gram, 1, 2, 1);
    let value1 = 500;
    runtime
        .block_on(oms.add_output(create_unblinded_output(
            TariScript::default(),
            OutputFeatures::default(),
            TestParamsHelpers::new(),
            MicroTari::from(value1),
        )))
        .unwrap();
    let value2 = 800;
    runtime
        .block_on(oms.add_output(create_unblinded_output(
            TariScript::default(),
            OutputFeatures::default(),
            TestParamsHelpers::new(),
            MicroTari::from(value2),
        )))
        .unwrap();

    match runtime.block_on(oms.prepare_transaction_to_send(
        OsRng.next_u64(),
        MicroTari::from(value1 + value2 + 1) - fee_without_change,
        MicroTari::from(20),
        None,
        "".to_string(),
        script!(Nop),
    )) {
        Err(OutputManagerError::NotEnoughFunds) => {},
        _ => panic!(),
    }
}

#[test]
fn receiving_and_confirmation() {
    let mut runtime = Runtime::new().unwrap();

    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let backend = OutputManagerSqliteDatabase::new(connection, None);

    let (mut oms, _shutdown, _, _, _, _, _) = setup_output_manager_service(&mut runtime, backend, true);

    let value = MicroTari::from(5000);
    let (tx_id, sender_message) = generate_sender_transaction_message(value);
    let rtp = runtime.block_on(oms.get_recipient_transaction(sender_message)).unwrap();
    assert_eq!(runtime.block_on(oms.get_unspent_outputs()).unwrap().len(), 0);
    assert_eq!(runtime.block_on(oms.get_pending_transactions()).unwrap().len(), 1);

    let output = match rtp.state {
        RecipientState::Finalized(s) => s.output,
        RecipientState::Failed(_) => panic!("Should not be in Failed state"),
    };

    runtime
        .block_on(oms.confirm_transaction(tx_id, vec![], vec![output]))
        .unwrap();

    assert_eq!(runtime.block_on(oms.get_pending_transactions()).unwrap().len(), 0);
    assert_eq!(runtime.block_on(oms.get_unspent_outputs()).unwrap().len(), 1);
}

#[test]
fn cancel_transaction() {
    let factories = CryptoFactories::default();

    let mut runtime = Runtime::new().unwrap();

    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let backend = OutputManagerSqliteDatabase::new(connection, None);

    let (mut oms, _shutdown, _, _, _, _, _) = setup_output_manager_service(&mut runtime, backend, true);

    let num_outputs = 20;
    for _i in 0..num_outputs {
        let (_ti, uo) = make_input(
            &mut OsRng.clone(),
            MicroTari::from(100 + OsRng.next_u64() % 1000),
            &factories.commitment,
        );
        runtime.block_on(oms.add_output(uo)).unwrap();
    }
    let stp = runtime
        .block_on(oms.prepare_transaction_to_send(
            OsRng.next_u64(),
            MicroTari::from(1000),
            MicroTari::from(20),
            None,
            "".to_string(),
            script!(Nop),
        ))
        .unwrap();

    match runtime.block_on(oms.cancel_transaction(1)) {
        Err(OutputManagerError::OutputManagerStorageError(OutputManagerStorageError::ValueNotFound)) => {},
        _ => panic!("Value should not exist"),
    }

    runtime
        .block_on(oms.cancel_transaction(stp.get_tx_id().unwrap()))
        .unwrap();

    assert_eq!(runtime.block_on(oms.get_unspent_outputs()).unwrap().len(), num_outputs);
}

#[test]
fn cancel_transaction_and_reinstate_inbound_tx() {
    let mut runtime = Runtime::new().unwrap();

    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let backend = OutputManagerSqliteDatabase::new(connection, None);

    let (mut oms, _shutdown, _, _, _, _, _) = setup_output_manager_service(&mut runtime, backend.clone(), true);

    let value = MicroTari::from(5000);
    let (tx_id, sender_message) = generate_sender_transaction_message(value);
    let _rtp = runtime.block_on(oms.get_recipient_transaction(sender_message)).unwrap();
    assert_eq!(runtime.block_on(oms.get_unspent_outputs()).unwrap().len(), 0);

    let pending_txs = runtime.block_on(oms.get_pending_transactions()).unwrap();

    assert_eq!(pending_txs.len(), 1);

    let output = pending_txs
        .get(&tx_id)
        .unwrap()
        .outputs_to_be_received
        .first()
        .unwrap()
        .clone();

    runtime.block_on(oms.cancel_transaction(tx_id)).unwrap();

    let cancelled_output = backend
        .fetch(&DbKey::OutputsByTxIdAndStatus(tx_id, OutputStatus::CancelledInbound))
        .unwrap()
        .unwrap();

    if let DbValue::AnyOutputs(o) = cancelled_output {
        let o = o.first().expect("Should be one output in here");
        assert_eq!(o.commitment, output.commitment);
    } else {
        panic!("Should have found cancelled output");
    }

    assert_eq!(runtime.block_on(oms.get_pending_transactions()).unwrap().len(), 0);

    runtime
        .block_on(oms.reinstate_cancelled_inbound_transaction(tx_id))
        .unwrap();

    assert_eq!(runtime.block_on(oms.get_pending_transactions()).unwrap().len(), 1);

    let balance = runtime.block_on(oms.get_balance()).unwrap();

    assert_eq!(balance.pending_incoming_balance, value);
}

#[test]
fn timeout_transaction() {
    let factories = CryptoFactories::default();

    let mut runtime = Runtime::new().unwrap();
    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let backend = OutputManagerSqliteDatabase::new(connection, None);

    let (mut oms, _shutdown, _, _, _, _, _) = setup_output_manager_service(&mut runtime, backend, true);

    let num_outputs = 20;
    for _i in 0..num_outputs {
        let (_ti, uo) = make_input(
            &mut OsRng.clone(),
            MicroTari::from(100 + OsRng.next_u64() % 1000),
            &factories.commitment,
        );
        runtime.block_on(oms.add_output(uo)).unwrap();
    }
    let _stp = runtime
        .block_on(oms.prepare_transaction_to_send(
            OsRng.next_u64(),
            MicroTari::from(1000),
            MicroTari::from(20),
            None,
            "".to_string(),
            script!(Nop),
        ))
        .unwrap();

    let remaining_outputs = runtime.block_on(oms.get_unspent_outputs()).unwrap().len();

    thread::sleep(Duration::from_millis(2));

    runtime
        .block_on(oms.timeout_transactions(Duration::from_millis(1000)))
        .unwrap();

    assert_eq!(
        runtime.block_on(oms.get_unspent_outputs()).unwrap().len(),
        remaining_outputs
    );

    runtime
        .block_on(oms.timeout_transactions(Duration::from_millis(1)))
        .unwrap();

    assert_eq!(runtime.block_on(oms.get_unspent_outputs()).unwrap().len(), num_outputs);
}

#[test]
fn test_get_balance() {
    let factories = CryptoFactories::default();
    let mut runtime = Runtime::new().unwrap();

    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let backend = OutputManagerSqliteDatabase::new(connection, None);

    let (mut oms, _shutdown, _, _, _, _, _) = setup_output_manager_service(&mut runtime, backend, true);

    let balance = runtime.block_on(oms.get_balance()).unwrap();

    assert_eq!(MicroTari::from(0), balance.available_balance);

    let mut total = MicroTari::from(0);
    let output_val = MicroTari::from(2000);
    let (_ti, uo) = make_input(&mut OsRng.clone(), output_val, &factories.commitment);
    total += uo.value;
    runtime.block_on(oms.add_output(uo)).unwrap();

    let (_ti, uo) = make_input(&mut OsRng.clone(), output_val, &factories.commitment);
    total += uo.value;
    runtime.block_on(oms.add_output(uo)).unwrap();

    let send_value = MicroTari::from(1000);
    let stp = runtime
        .block_on(oms.prepare_transaction_to_send(
            OsRng.next_u64(),
            send_value,
            MicroTari::from(20),
            None,
            "".to_string(),
            script!(Nop),
        ))
        .unwrap();

    let change_val = stp.get_change_amount().unwrap();

    let recv_value = MicroTari::from(1500);
    let (_tx_id, sender_message) = generate_sender_transaction_message(recv_value);
    let _rtp = runtime.block_on(oms.get_recipient_transaction(sender_message)).unwrap();

    let balance = runtime.block_on(oms.get_balance()).unwrap();

    assert_eq!(output_val, balance.available_balance);
    assert_eq!(recv_value + change_val, balance.pending_incoming_balance);
    assert_eq!(output_val, balance.pending_outgoing_balance);
}

#[test]
fn test_confirming_received_output() {
    let mut runtime = Runtime::new().unwrap();

    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let backend = OutputManagerSqliteDatabase::new(connection, None);

    let (mut oms, _shutdown, _, _, _, _, _) = setup_output_manager_service(&mut runtime, backend, true);

    let value = MicroTari::from(5000);
    let (tx_id, sender_message) = generate_sender_transaction_message(value);
    let rtp = runtime.block_on(oms.get_recipient_transaction(sender_message)).unwrap();
    assert_eq!(runtime.block_on(oms.get_unspent_outputs()).unwrap().len(), 0);
    assert_eq!(runtime.block_on(oms.get_pending_transactions()).unwrap().len(), 1);

    let output = match rtp.state {
        RecipientState::Finalized(s) => s.output,
        RecipientState::Failed(_) => panic!("Should not be in Failed state"),
    };
    runtime
        .block_on(oms.confirm_transaction(tx_id, vec![], vec![output.clone()]))
        .unwrap();
    assert_eq!(runtime.block_on(oms.get_balance()).unwrap().available_balance, value);

    let factories = CryptoFactories::default();
    let rewind_public_keys = runtime.block_on(oms.get_rewind_public_keys()).unwrap();
    let rewind_result = output
        .rewind_range_proof_value_only(
            &factories.range_proof,
            &rewind_public_keys.rewind_public_key,
            &rewind_public_keys.rewind_blinding_public_key,
        )
        .unwrap();
    assert_eq!(rewind_result.committed_value, value);
}

#[test]
fn sending_transaction_with_short_term_clear() {
    let factories = CryptoFactories::default();
    let mut runtime = Runtime::new().unwrap();

    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let backend = OutputManagerSqliteDatabase::new(connection, None);

    let (mut oms, _shutdown, _, _, _, _, _) = setup_output_manager_service(&mut runtime, backend.clone(), true);

    let available_balance = 10_000 * uT;
    let (_ti, uo) = make_input(&mut OsRng.clone(), available_balance, &factories.commitment);
    runtime.block_on(oms.add_output(uo)).unwrap();

    // Check that funds are encumbered and then unencumbered if the pending tx is not confirmed before restart
    let _stp = runtime
        .block_on(oms.prepare_transaction_to_send(
            OsRng.next_u64(),
            MicroTari::from(1000),
            MicroTari::from(20),
            None,
            "".to_string(),
            script!(Nop),
        ))
        .unwrap();

    let balance = runtime.block_on(oms.get_balance()).unwrap();
    let expected_change = balance.pending_incoming_balance;
    assert_eq!(balance.pending_outgoing_balance, available_balance);

    drop(oms);
    let (mut oms, _shutdown, _, _, _, _, _) = setup_output_manager_service(&mut runtime, backend.clone(), true);

    let balance = runtime.block_on(oms.get_balance()).unwrap();
    assert_eq!(balance.available_balance, available_balance);

    // Check that a unconfirm Pending Transaction can be cancelled
    let stp = runtime
        .block_on(oms.prepare_transaction_to_send(
            OsRng.next_u64(),
            MicroTari::from(1000),
            MicroTari::from(20),
            None,
            "".to_string(),
            script!(Nop),
        ))
        .unwrap();
    let sender_tx_id = stp.get_tx_id().unwrap();

    let balance = runtime.block_on(oms.get_balance()).unwrap();
    assert_eq!(balance.pending_outgoing_balance, available_balance);
    runtime.block_on(oms.cancel_transaction(sender_tx_id)).unwrap();

    let balance = runtime.block_on(oms.get_balance()).unwrap();
    assert_eq!(balance.available_balance, available_balance);

    // Check that is the pending tx is confirmed that the encumberance persists after restart
    let stp = runtime
        .block_on(oms.prepare_transaction_to_send(
            OsRng.next_u64(),
            MicroTari::from(1000),
            MicroTari::from(20),
            None,
            "".to_string(),
            script!(Nop),
        ))
        .unwrap();
    let sender_tx_id = stp.get_tx_id().unwrap();
    runtime.block_on(oms.confirm_pending_transaction(sender_tx_id)).unwrap();

    drop(oms);
    let (mut oms, _shutdown, _, _, _, _, _) = setup_output_manager_service(&mut runtime, backend, true);

    let balance = runtime.block_on(oms.get_balance()).unwrap();
    assert_eq!(balance.pending_outgoing_balance, available_balance);

    let tx = runtime.block_on(complete_transaction(stp, oms.clone()));

    runtime
        .block_on(oms.confirm_transaction(sender_tx_id, tx.body.inputs().clone(), tx.body.outputs().clone()))
        .unwrap();

    let balance = runtime.block_on(oms.get_balance()).unwrap();
    assert_eq!(balance.available_balance, expected_change);
}

#[test]
fn coin_split_with_change() {
    let factories = CryptoFactories::default();
    let mut runtime = Runtime::new().unwrap();
    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let backend = OutputManagerSqliteDatabase::new(connection, None);
    let (mut oms, _shutdown, _, _, _, _, _) = setup_output_manager_service(&mut runtime, backend, true);

    let val1 = 6_000 * uT;
    let val2 = 7_000 * uT;
    let val3 = 8_000 * uT;
    let (_ti, uo1) = make_input(&mut OsRng.clone(), val1, &factories.commitment);
    let (_ti, uo2) = make_input(&mut OsRng.clone(), val2, &factories.commitment);
    let (_ti, uo3) = make_input(&mut OsRng.clone(), val3, &factories.commitment);
    assert!(runtime.block_on(oms.add_output(uo1)).is_ok());
    assert!(runtime.block_on(oms.add_output(uo2)).is_ok());
    assert!(runtime.block_on(oms.add_output(uo3)).is_ok());

    let fee_per_gram = MicroTari::from(25);
    let split_count = 8;
    let (_tx_id, coin_split_tx, fee, amount) = runtime
        .block_on(oms.create_coin_split(1000.into(), split_count, fee_per_gram, None))
        .unwrap();
    assert_eq!(coin_split_tx.body.inputs().len(), 2);
    assert_eq!(coin_split_tx.body.outputs().len(), split_count + 1);
    assert_eq!(fee, Fee::calculate(fee_per_gram, 1, 2, split_count + 1));
    assert_eq!(amount, val2 + val3);
}

#[test]
fn coin_split_no_change() {
    let factories = CryptoFactories::default();
    let mut runtime = Runtime::new().unwrap();
    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let backend = OutputManagerSqliteDatabase::new(connection, None);
    let (mut oms, _shutdown, _, _, _, _, _) = setup_output_manager_service(&mut runtime, backend, true);

    let fee_per_gram = MicroTari::from(25);
    let split_count = 15;
    let fee = Fee::calculate(fee_per_gram, 1, 3, 15);
    let val1 = 4_000 * uT;
    let val2 = 5_000 * uT;
    let val3 = 6_000 * uT + fee;
    let (_ti, uo1) = make_input(&mut OsRng.clone(), val1, &factories.commitment);
    let (_ti, uo2) = make_input(&mut OsRng.clone(), val2, &factories.commitment);
    let (_ti, uo3) = make_input(&mut OsRng.clone(), val3, &factories.commitment);
    assert!(runtime.block_on(oms.add_output(uo1)).is_ok());
    assert!(runtime.block_on(oms.add_output(uo2)).is_ok());
    assert!(runtime.block_on(oms.add_output(uo3)).is_ok());

    let (_tx_id, coin_split_tx, fee, amount) = runtime
        .block_on(oms.create_coin_split(1000.into(), split_count, fee_per_gram, None))
        .unwrap();
    assert_eq!(coin_split_tx.body.inputs().len(), 3);
    assert_eq!(coin_split_tx.body.outputs().len(), split_count);
    assert_eq!(fee, Fee::calculate(fee_per_gram, 1, 3, split_count));
    assert_eq!(amount, val1 + val2 + val3);
}

#[test]
fn handle_coinbase() {
    let mut runtime = Runtime::new().unwrap();
    let factories = CryptoFactories::default();
    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let backend = OutputManagerSqliteDatabase::new(connection, None);
    let (mut oms, _shutdown, _, _, _, _, _) = setup_output_manager_service(&mut runtime, backend, true);

    let reward1 = MicroTari::from(1000);
    let fees1 = MicroTari::from(500);
    let value1 = reward1 + fees1;
    let reward2 = MicroTari::from(2000);
    let fees2 = MicroTari::from(500);
    let value2 = reward2 + fees2;
    let reward3 = MicroTari::from(3000);
    let fees3 = MicroTari::from(500);
    let value3 = reward3 + fees3;

    let _ = runtime
        .block_on(oms.get_coinbase_transaction(1, reward1, fees1, 1))
        .unwrap();
    assert_eq!(runtime.block_on(oms.get_unspent_outputs()).unwrap().len(), 0);
    assert_eq!(runtime.block_on(oms.get_pending_transactions()).unwrap().len(), 1);
    assert_eq!(
        runtime.block_on(oms.get_balance()).unwrap().pending_incoming_balance,
        value1
    );
    let _tx2 = runtime
        .block_on(oms.get_coinbase_transaction(2, reward2, fees2, 1))
        .unwrap();
    assert_eq!(runtime.block_on(oms.get_unspent_outputs()).unwrap().len(), 0);
    assert_eq!(runtime.block_on(oms.get_pending_transactions()).unwrap().len(), 1);
    assert_eq!(
        runtime.block_on(oms.get_balance()).unwrap().pending_incoming_balance,
        value2
    );
    let tx3 = runtime
        .block_on(oms.get_coinbase_transaction(3, reward3, fees3, 2))
        .unwrap();
    assert_eq!(runtime.block_on(oms.get_unspent_outputs()).unwrap().len(), 0);
    assert_eq!(runtime.block_on(oms.get_pending_transactions()).unwrap().len(), 2);
    assert_eq!(
        runtime.block_on(oms.get_balance()).unwrap().pending_incoming_balance,
        value2 + value3
    );

    let output = tx3.body.outputs()[0].clone();

    let rewind_public_keys = runtime.block_on(oms.get_rewind_public_keys()).unwrap();
    let rewind_result = output
        .rewind_range_proof_value_only(
            &factories.range_proof,
            &rewind_public_keys.rewind_public_key,
            &rewind_public_keys.rewind_blinding_public_key,
        )
        .unwrap();
    assert_eq!(rewind_result.committed_value, value3);

    runtime
        .block_on(oms.confirm_transaction(3, vec![], vec![output]))
        .unwrap();

    assert_eq!(runtime.block_on(oms.get_pending_transactions()).unwrap().len(), 1);
    assert_eq!(runtime.block_on(oms.get_unspent_outputs()).unwrap().len(), 1);
    assert_eq!(runtime.block_on(oms.get_balance()).unwrap().available_balance, value3);
    assert_eq!(
        runtime.block_on(oms.get_balance()).unwrap().pending_incoming_balance,
        value2
    );
    assert_eq!(
        runtime.block_on(oms.get_balance()).unwrap().pending_outgoing_balance,
        MicroTari::from(0)
    );
}

#[test]
fn test_utxo_stxo_invalid_txo_validation() {
    let factories = CryptoFactories::default();

    let mut runtime = Runtime::new().unwrap();
    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let backend = OutputManagerSqliteDatabase::new(connection, None);

    let invalid_value = 666;
    let invalid_output = create_unblinded_output(
        TariScript::default(),
        OutputFeatures::default(),
        TestParamsHelpers::new(),
        MicroTari::from(invalid_value),
    );
    let invalid_tx_output = invalid_output.as_transaction_output(&factories).unwrap();

    let invalid_db_output = DbUnblindedOutput::from_unblinded_output(invalid_output.clone(), &factories).unwrap();
    backend
        .write(WriteOperation::Insert(DbKeyValuePair::UnspentOutput(
            invalid_db_output.commitment.clone(),
            Box::new(invalid_db_output),
        )))
        .unwrap();
    backend
        .invalidate_unspent_output(
            &DbUnblindedOutput::from_unblinded_output(invalid_output.clone(), &factories).unwrap(),
        )
        .unwrap();

    let spent_value1 = 500;
    let spent_output1 = create_unblinded_output(
        TariScript::default(),
        OutputFeatures::default(),
        TestParamsHelpers::new(),
        MicroTari::from(spent_value1),
    );
    let spent_tx_output1 = spent_output1.as_transaction_output(&factories).unwrap();
    let spent_db_output1 = DbUnblindedOutput::from_unblinded_output(spent_output1.clone(), &factories).unwrap();

    backend
        .write(WriteOperation::Insert(DbKeyValuePair::SpentOutput(
            spent_db_output1.commitment.clone(),
            Box::new(spent_db_output1),
        )))
        .unwrap();

    let spent_value2 = 800;
    let spent_output2 = create_unblinded_output(
        TariScript::default(),
        OutputFeatures::default(),
        TestParamsHelpers::new(),
        MicroTari::from(spent_value2),
    );

    let spent_db_output2 = DbUnblindedOutput::from_unblinded_output(spent_output2, &factories).unwrap();
    backend
        .write(WriteOperation::Insert(DbKeyValuePair::SpentOutput(
            spent_db_output2.commitment.clone(),
            Box::new(spent_db_output2),
        )))
        .unwrap();

    let (mut oms, _shutdown, _ts, _mock_rpc_server, server_node_identity, rpc_service_state, _) =
        setup_output_manager_service(&mut runtime, backend, true);
    let mut event_stream = oms.get_event_stream_fused();

    let unspent_value1 = 500;
    let unspent_output1 = create_unblinded_output(
        TariScript::default(),
        OutputFeatures::default(),
        TestParamsHelpers::new(),
        MicroTari::from(unspent_value1),
    );
    let unspent_tx_output1 = unspent_output1.as_transaction_output(&factories).unwrap();

    runtime.block_on(oms.add_output(unspent_output1.clone())).unwrap();

    let unspent_value2 = 800;
    let unspent_output2 = create_unblinded_output(
        TariScript::default(),
        OutputFeatures::default(),
        TestParamsHelpers::new(),
        MicroTari::from(unspent_value2),
    );

    runtime.block_on(oms.add_output(unspent_output2)).unwrap();

    let unspent_value3 = 900;
    let unspent_output3 = create_unblinded_output(
        TariScript::default(),
        OutputFeatures::default(),
        TestParamsHelpers::new(),
        MicroTari::from(unspent_value3),
    );
    let unspent_tx_output3 = unspent_output3.as_transaction_output(&factories).unwrap();

    runtime.block_on(oms.add_output(unspent_output3.clone())).unwrap();

    let unspent_value4 = 901;
    let unspent_output4 = create_unblinded_output(
        TariScript::default(),
        OutputFeatures::default(),
        TestParamsHelpers::new(),
        MicroTari::from(unspent_value4),
    );
    let unspent_tx_output4 = unspent_output4.as_transaction_output(&factories).unwrap();

    runtime.block_on(oms.add_output(unspent_output4.clone())).unwrap();

    rpc_service_state.set_utxos(vec![invalid_output.as_transaction_output(&factories).unwrap()]);

    runtime
        .block_on(oms.set_base_node_public_key(server_node_identity.public_key().clone()))
        .unwrap();

    runtime
        .block_on(oms.validate_txos(TxoValidationType::Invalid, ValidationRetryStrategy::Limited(5)))
        .unwrap();

    let _fetch_utxo_calls = runtime
        .block_on(rpc_service_state.wait_pop_fetch_utxos_calls(1, Duration::from_secs(60)))
        .unwrap();

    runtime.block_on(async {
        let mut delay = delay_for(Duration::from_secs(60)).fuse();
        let mut success = false;
        loop {
            futures::select! {
                event = event_stream.select_next_some() => {
                    if let Ok(msg) = event {
                        if let OutputManagerEvent::TxoValidationSuccess(_,TxoValidationType::Invalid) = (*msg).clone() {
                                   success = true;
                                   break;
                                };
                        }
                },
                () = delay => {
                    break;
                },
            }
        }
        assert!(success, "Did not receive validation success event");
    });

    let outputs = runtime.block_on(oms.get_unspent_outputs()).unwrap();

    assert_eq!(outputs.len(), 5);

    rpc_service_state.set_utxos(vec![
        unspent_tx_output1,
        invalid_tx_output,
        unspent_tx_output4,
        unspent_tx_output3,
    ]);

    runtime
        .block_on(oms.validate_txos(TxoValidationType::Unspent, ValidationRetryStrategy::UntilSuccess))
        .unwrap();

    let _fetch_utxo_calls = runtime
        .block_on(rpc_service_state.wait_pop_fetch_utxos_calls(3, Duration::from_secs(60)))
        .unwrap();

    runtime.block_on(async {
        let mut delay = delay_for(Duration::from_secs(60)).fuse();
        let mut success = false;
        loop {
            futures::select! {
                event = event_stream.select_next_some() => {
                if let Ok(msg) = event {
                                if let OutputManagerEvent::TxoValidationSuccess(_,TxoValidationType::Unspent) = (*msg).clone() {
                                   success = true;
                                   break;
                                };
                                };
                },
                () = delay => {
                    break;
                },
            }
        }
        assert!(success, "Did not receive validation success event");
    });

    let outputs = runtime.block_on(oms.get_unspent_outputs()).unwrap();

    assert_eq!(outputs.len(), 4);
    assert!(outputs.iter().any(|o| o == &unspent_output1));
    assert!(outputs.iter().any(|o| o == &unspent_output3));
    assert!(outputs.iter().any(|o| o == &unspent_output4));
    assert!(outputs.iter().any(|o| o == &invalid_output));

    rpc_service_state.set_utxos(vec![spent_tx_output1]);

    runtime
        .block_on(oms.validate_txos(TxoValidationType::Spent, ValidationRetryStrategy::UntilSuccess))
        .unwrap();

    let _fetch_utxo_calls = runtime
        .block_on(rpc_service_state.wait_pop_fetch_utxos_calls(1, Duration::from_secs(60)))
        .unwrap();

    runtime.block_on(async {
        let mut delay = delay_for(Duration::from_secs(60)).fuse();
        let mut success = false;
        loop {
            futures::select! {
                event = event_stream.select_next_some() => {
                    if let Ok(msg) = event {
                            if let OutputManagerEvent::TxoValidationSuccess(_, TxoValidationType::Spent) = (*msg).clone() {
                                   success = true;
                                   break;
                                };
                    }
                },
                () = delay => {
                    break;
                },
            }
        }
        assert!(success, "Did not receive validation success event");
    });

    let outputs = runtime.block_on(oms.get_unspent_outputs()).unwrap();

    assert_eq!(outputs.len(), 5);
    assert!(outputs.iter().any(|o| o == &spent_output1));
}

#[test]
fn test_base_node_switch_during_validation() {
    let factories = CryptoFactories::default();

    let mut runtime = Runtime::new().unwrap();
    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let backend = OutputManagerSqliteDatabase::new(connection, None);

    let (
        mut oms,
        _shutdown,
        _ts,
        _mock_rpc_server,
        server_node_identity,
        mut rpc_service_state,
        _connectivity_mock_state,
    ) = setup_output_manager_service(&mut runtime, backend, true);
    let mut event_stream = oms.get_event_stream_fused();

    let unspent_value1 = 500;
    let unspent_output1 = create_unblinded_output(
        TariScript::default(),
        OutputFeatures::default(),
        TestParamsHelpers::new(),
        MicroTari::from(unspent_value1),
    );
    let unspent_tx_output1 = unspent_output1.as_transaction_output(&factories).unwrap();

    runtime.block_on(oms.add_output(unspent_output1)).unwrap();

    let unspent_value2 = 800;
    let unspent_output2 = create_unblinded_output(
        TariScript::default(),
        OutputFeatures::default(),
        TestParamsHelpers::new(),
        MicroTari::from(unspent_value2),
    );

    runtime.block_on(oms.add_output(unspent_output2)).unwrap();

    let unspent_value3 = 900;
    let unspent_output3 = create_unblinded_output(
        TariScript::default(),
        OutputFeatures::default(),
        TestParamsHelpers::new(),
        MicroTari::from(unspent_value3),
    );
    let unspent_tx_output3 = unspent_output3.as_transaction_output(&factories).unwrap();

    runtime.block_on(oms.add_output(unspent_output3)).unwrap();

    // First RPC server state
    rpc_service_state.set_utxos(vec![unspent_tx_output1, unspent_tx_output3]);
    rpc_service_state.set_response_delay(Some(Duration::from_secs(8)));

    // New base node we will switch to
    let new_server_node_identity = build_node_identity(PeerFeatures::COMMUNICATION_NODE);

    runtime
        .block_on(oms.set_base_node_public_key(server_node_identity.public_key().clone()))
        .unwrap();

    runtime
        .block_on(oms.validate_txos(TxoValidationType::Unspent, ValidationRetryStrategy::UntilSuccess))
        .unwrap();

    let _fetch_utxo_calls = runtime
        .block_on(rpc_service_state.wait_pop_fetch_utxos_calls(1, Duration::from_secs(60)))
        .unwrap();

    runtime
        .block_on(oms.set_base_node_public_key(new_server_node_identity.public_key().clone()))
        .unwrap();

    runtime.block_on(async {
        let mut delay = delay_for(Duration::from_secs(60)).fuse();
        let mut abort = false;
        loop {
            futures::select! {
                event = event_stream.select_next_some() => {
                if let Ok(msg) = event {
                       if let OutputManagerEvent::TxoValidationAborted(_,_) = (*msg).clone() {
                               abort = true;
                               break;
                        }
                     }
                },
                () = delay => {
                    break;
                },
            }
        }
        assert!(abort, "Did not receive validation abort");
    });
}

#[test]
fn test_txo_validation_connection_timeout_retries() {
    let mut runtime = Runtime::new().unwrap();
    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let backend = OutputManagerSqliteDatabase::new(connection, None);

    let (mut oms, _shutdown, _ts, _mock_rpc_server, server_node_identity, _rpc_service_state, _connectivity_mock_state) =
        setup_output_manager_service(&mut runtime, backend, false);
    let mut event_stream = oms.get_event_stream_fused();

    let unspent_value1 = 500;
    let unspent_output1 = create_unblinded_output(
        TariScript::default(),
        OutputFeatures::default(),
        TestParamsHelpers::new(),
        MicroTari::from(unspent_value1),
    );

    runtime.block_on(oms.add_output(unspent_output1)).unwrap();

    let unspent_value2 = 800;
    let unspent_output2 = create_unblinded_output(
        TariScript::default(),
        OutputFeatures::default(),
        TestParamsHelpers::new(),
        MicroTari::from(unspent_value2),
    );

    runtime.block_on(oms.add_output(unspent_output2)).unwrap();

    runtime
        .block_on(oms.set_base_node_public_key(server_node_identity.public_key().clone()))
        .unwrap();

    runtime
        .block_on(oms.validate_txos(TxoValidationType::Unspent, ValidationRetryStrategy::Limited(1)))
        .unwrap();

    runtime.block_on(async {
        let mut delay = delay_for(Duration::from_secs(60)).fuse();
        let mut timeout = 0;
        let mut failed = 0;
        loop {
            futures::select! {
                event = event_stream.select_next_some() => {
                        if let Ok(msg) = event {
                            match (*msg).clone() {
                                OutputManagerEvent::TxoValidationTimedOut(_,_) => {
                                   timeout+=1;
                                },
                                 OutputManagerEvent::TxoValidationFailure(_,_) => {
                                   failed+=1;
                                },
                                _ => (),
                            }
                        };
                    if timeout+failed >= 3 {
                        break;
                    }
                },
                () = delay => {
                    break;
                },
            }
        }
        assert_eq!(failed, 1);
        assert_eq!(timeout, 2);
    });
}

#[test]
fn test_txo_validation_rpc_error_retries() {
    let mut runtime = Runtime::new().unwrap();
    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let backend = OutputManagerSqliteDatabase::new(connection, None);

    let (mut oms, _shutdown, _ts, _mock_rpc_server, server_node_identity, rpc_service_state, _connectivity_mock_state) =
        setup_output_manager_service(&mut runtime, backend, true);
    let mut event_stream = oms.get_event_stream_fused();
    rpc_service_state.set_rpc_status_error(Some(RpcStatus::bad_request("blah".to_string())));

    let unspent_value1 = 500;
    let unspent_output1 = create_unblinded_output(
        TariScript::default(),
        OutputFeatures::default(),
        TestParamsHelpers::new(),
        MicroTari::from(unspent_value1),
    );

    runtime.block_on(oms.add_output(unspent_output1)).unwrap();

    let unspent_value2 = 800;
    let unspent_output2 = create_unblinded_output(
        TariScript::default(),
        OutputFeatures::default(),
        TestParamsHelpers::new(),
        MicroTari::from(unspent_value2),
    );

    runtime.block_on(oms.add_output(unspent_output2)).unwrap();

    runtime
        .block_on(oms.set_base_node_public_key(server_node_identity.public_key().clone()))
        .unwrap();

    runtime
        .block_on(oms.validate_txos(TxoValidationType::Unspent, ValidationRetryStrategy::Limited(1)))
        .unwrap();

    runtime.block_on(async {
        let mut delay = delay_for(Duration::from_secs(60)).fuse();
        let mut failed = 0;
        loop {
            futures::select! {
                event = event_stream.select_next_some() => {
                    if let Ok(msg) = event {
                                         if let OutputManagerEvent::TxoValidationFailure(_,_) = (*msg).clone() {
                            failed+=1;
                        }
                     }

                    if failed >= 1 {
                        break;
                    }
                },
                () = delay => {
                    break;
                },
            }
        }
        assert_eq!(failed, 1);
    });
}

#[test]
fn test_txo_validation_rpc_timeout() {
    let mut runtime = Runtime::new().unwrap();
    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let backend = OutputManagerSqliteDatabase::new(connection, None);

    let (
        mut oms,
        _shutdown,
        _ts,
        _mock_rpc_server,
        server_node_identity,
        mut rpc_service_state,
        _connectivity_mock_state,
    ) = setup_output_manager_service(&mut runtime, backend, true);
    let mut event_stream = oms.get_event_stream_fused();
    rpc_service_state.set_response_delay(Some(Duration::from_secs(120)));

    let unspent_value1 = 500;
    let unspent_output1 = create_unblinded_output(
        TariScript::default(),
        OutputFeatures::default(),
        TestParamsHelpers::new(),
        MicroTari::from(unspent_value1),
    );

    runtime.block_on(oms.add_output(unspent_output1)).unwrap();

    let unspent_value2 = 800;
    let unspent_output2 = create_unblinded_output(
        TariScript::default(),
        OutputFeatures::default(),
        TestParamsHelpers::new(),
        MicroTari::from(unspent_value2),
    );

    runtime.block_on(oms.add_output(unspent_output2)).unwrap();

    runtime
        .block_on(oms.set_base_node_public_key(server_node_identity.public_key().clone()))
        .unwrap();

    runtime
        .block_on(oms.validate_txos(TxoValidationType::Unspent, ValidationRetryStrategy::Limited(1)))
        .unwrap();

    runtime.block_on(async {
        let mut delay = delay_for(Duration::from_secs(60)).fuse();
        let mut failed = 0;
        loop {
            futures::select! {
                event = event_stream.select_next_some() => {
                    if let Ok(msg) = event {
                         if let OutputManagerEvent::TxoValidationFailure(_,_) = (*msg).clone() {
                         failed+=1;
                        }
                    }

                    if failed >= 1 {
                        break;
                    }
                },
                () = delay => {
                    break;
                },
            }
        }
        assert_eq!(failed, 1);
    });
}

#[test]
fn test_txo_validation_base_node_not_synced() {
    let factories = CryptoFactories::default();

    let mut runtime = Runtime::new().unwrap();
    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let backend = OutputManagerSqliteDatabase::new(connection, None);

    let (mut oms, _shutdown, _ts, _mock_rpc_server, server_node_identity, rpc_service_state, _connectivity_mock_state) =
        setup_output_manager_service(&mut runtime, backend, true);
    let mut event_stream = oms.get_event_stream_fused();
    rpc_service_state.set_is_synced(false);

    let unspent_value1 = 500;
    let unspent_output1 = create_unblinded_output(
        TariScript::default(),
        OutputFeatures::default(),
        TestParamsHelpers::new(),
        MicroTari::from(unspent_value1),
    );
    let unspent_tx_output1 = unspent_output1.as_transaction_output(&factories).unwrap();

    runtime.block_on(oms.add_output(unspent_output1.clone())).unwrap();

    let unspent_value2 = 800;
    let unspent_output2 = create_unblinded_output(
        TariScript::default(),
        OutputFeatures::default(),
        TestParamsHelpers::new(),
        MicroTari::from(unspent_value2),
    );

    runtime.block_on(oms.add_output(unspent_output2)).unwrap();

    runtime
        .block_on(oms.set_base_node_public_key(server_node_identity.public_key().clone()))
        .unwrap();

    runtime
        .block_on(oms.validate_txos(TxoValidationType::Unspent, ValidationRetryStrategy::Limited(5)))
        .unwrap();

    runtime.block_on(async {
        let mut delay = delay_for(Duration::from_secs(60)).fuse();
        let mut delayed = 0;
        loop {
            futures::select! {
                event = event_stream.select_next_some() => {
                    if let Ok(msg) = event {
                            if let OutputManagerEvent::TxoValidationDelayed(_,_) = (*msg).clone() {
                                delayed+=1;
                            }
                    }
                    if delayed >= 2 {
                        break;
                    }
                },
                () = delay => {
                    break;
                },
            }
        }
        assert_eq!(delayed, 2);
    });

    rpc_service_state.set_is_synced(true);
    rpc_service_state.set_utxos(vec![unspent_tx_output1]);

    runtime.block_on(async {
        let mut delay = delay_for(Duration::from_secs(60)).fuse();
        let mut success = false;
        loop {
            futures::select! {
                            event = event_stream.select_next_some() => {
                                if let Ok(msg) = event {
             if let OutputManagerEvent::TxoValidationSuccess(_,_) = (*msg).clone() {
            success = true;
            break;
             }
                                }
                            },
                            () = delay => {
                                break;
                            },
                        }
        }
        assert!(success, "Did not receive validation success event");
    });

    let outputs = runtime.block_on(oms.get_unspent_outputs()).unwrap();

    assert_eq!(outputs.len(), 1);
    assert!(outputs.iter().any(|o| o == &unspent_output1));
}

#[test]
fn test_oms_key_manager_discrepancy() {
    let shutdown = Shutdown::new();
    let factories = CryptoFactories::default();
    let mut runtime = Runtime::new().unwrap();
    let (_oms_request_sender, oms_request_receiver) = reply_channel::unbounded();

    let (oms_event_publisher, _) = broadcast::channel(200);
    let (ts_request_sender, _ts_request_receiver) = reply_channel::unbounded();
    let (event_publisher, _) = channel(100);
    let ts_handle = TransactionServiceHandle::new(ts_request_sender, event_publisher);
    let constants = ConsensusConstantsBuilder::new(Network::Weatherwax).build();
    let (sender, receiver_bns) = reply_channel::unbounded();
    let (event_publisher_bns, _) = broadcast::channel(100);

    let basenode_service_handle = BaseNodeServiceHandle::new(sender, event_publisher_bns);
    let mut mock_base_node_service = MockBaseNodeService::new(receiver_bns, shutdown.to_signal());
    mock_base_node_service.set_default_base_node_state();
    runtime.spawn(mock_base_node_service.run());

    let (connectivity_manager, _connectivity_mock) = create_connectivity_mock();

    let (connection, _tempdir) = get_temp_sqlite_database_connection();
    let db = OutputManagerDatabase::new(OutputManagerSqliteDatabase::new(connection, None));

    let master_key1 = CommsSecretKey::random(&mut OsRng);

    let output_manager_service = runtime
        .block_on(OutputManagerService::new(
            OutputManagerServiceConfig::default(),
            ts_handle.clone(),
            oms_request_receiver,
            db.clone(),
            oms_event_publisher.clone(),
            factories.clone(),
            constants.clone(),
            shutdown.to_signal(),
            basenode_service_handle.clone(),
            connectivity_manager.clone(),
            master_key1.clone(),
        ))
        .unwrap();

    drop(output_manager_service);

    let (_oms_request_sender2, oms_request_receiver2) = reply_channel::unbounded();
    let output_manager_service2 = runtime
        .block_on(OutputManagerService::new(
            OutputManagerServiceConfig::default(),
            ts_handle.clone(),
            oms_request_receiver2,
            db.clone(),
            oms_event_publisher.clone(),
            factories.clone(),
            constants.clone(),
            shutdown.to_signal(),
            basenode_service_handle.clone(),
            connectivity_manager.clone(),
            master_key1,
        ))
        .expect("Should be able to make a new OMS with same master key");
    drop(output_manager_service2);

    let (_oms_request_sender3, oms_request_receiver3) = reply_channel::unbounded();
    let master_key2 = CommsSecretKey::random(&mut OsRng);
    let output_manager_service3 = runtime.block_on(OutputManagerService::new(
        OutputManagerServiceConfig::default(),
        ts_handle,
        oms_request_receiver3,
        db,
        oms_event_publisher,
        factories,
        constants,
        shutdown.to_signal(),
        basenode_service_handle,
        connectivity_manager,
        master_key2,
    ));

    assert!(matches!(
        output_manager_service3,
        Err(OutputManagerError::MasterSecretKeyMismatch)
    ));
}

#[test]
fn get_coinbase_tx_for_same_height() {
    let (connection, _tempdir) = get_temp_sqlite_database_connection();

    let mut runtime = Runtime::new().unwrap();
    let (mut oms, _shutdown, _, _, _, _, _) =
        setup_output_manager_service(&mut runtime, OutputManagerSqliteDatabase::new(connection, None), true);

    runtime
        .block_on(oms.get_coinbase_transaction(1, 100_000.into(), 100.into(), 1))
        .unwrap();

    let pending_transactions = runtime.block_on(oms.get_pending_transactions()).unwrap();
    assert!(pending_transactions.values().any(|p| p.tx_id == 1));

    runtime
        .block_on(oms.get_coinbase_transaction(2, 100_000.into(), 100.into(), 1))
        .unwrap();

    let pending_transactions = runtime.block_on(oms.get_pending_transactions()).unwrap();
    assert!(!pending_transactions.values().any(|p| p.tx_id == 1));
    assert!(pending_transactions.values().any(|p| p.tx_id == 2));
}
