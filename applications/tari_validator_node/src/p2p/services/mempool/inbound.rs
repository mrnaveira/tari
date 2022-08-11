use std::{convert::TryInto, sync::Arc};

use futures::{pin_mut, Stream, StreamExt};
use log::{error, warn};
use tari_crypto::{ristretto::RistrettoPublicKey, tari_utilities::ByteArray};
use tari_dan_core::services::mempool::service::{MempoolService, MempoolServiceHandle};
use tari_dan_engine::instructions::Instruction;
use tari_p2p::{
    comms_connector::{PeerMessage, SubscriptionFactory},
    domain_message::DomainMessage,
    tari_message::TariMessageType,
};

use crate::p2p::proto::validator_node::InvokeMethodRequest;

const LOG_TARGET: &str = "tari::validator_node::p2p::services::mempool::inbound";

const SUBSCRIPTION_LABEL: &str = "MempoolInbound";

#[derive(Clone)]
pub struct TariCommsMempoolInboundHandle {
    inbound_message_subscription_factory: Arc<SubscriptionFactory>,
    mempool: MempoolServiceHandle,
}

impl TariCommsMempoolInboundHandle {
    pub fn new(inbound_message_subscription_factory: Arc<SubscriptionFactory>, mempool: MempoolServiceHandle) -> Self {
        Self {
            inbound_message_subscription_factory,
            mempool,
        }
    }

    fn inbound_transaction_stream(&self) -> impl Stream<Item = DomainMessage<Instruction>> {
        self.inbound_message_subscription_factory
            .get_subscription(TariMessageType::DanMempoolTransaction, SUBSCRIPTION_LABEL)
            .filter_map(extract_transaction)
    }

    pub async fn run(&mut self) {
        let inbound_transaction_stream = self.inbound_transaction_stream().fuse();
        pin_mut!(inbound_transaction_stream);

        loop {
            let mempool_service = self.mempool.clone();
            tokio::select! {
                Some(domain_msg) = inbound_transaction_stream.next() => {
                    handle_incoming_transaction(mempool_service, domain_msg).await;
                },
            }
        }
    }
}

async fn handle_incoming_transaction(
    mut mempool: MempoolServiceHandle,
    domain_request_msg: DomainMessage<Instruction>,
) {
    let (_, instruction) = domain_request_msg.into_origin_and_inner();

    let result = mempool.submit_instruction(instruction).await;

    if let Err(e) = result {
        error!(
            target: LOG_TARGET,
            "Error handling incoming mempool transaction. {}",
            e.to_string()
        );
    }
}

async fn extract_transaction(msg: Arc<PeerMessage>) -> Option<DomainMessage<Instruction>> {
    match msg.decode_message::<InvokeMethodRequest>() {
        Err(e) => {
            warn!(
                target: LOG_TARGET,
                "Could not decode inbound transaction message. {}",
                e.to_string()
            );
            None
        },
        Ok(tx) => {
            // TODO: implement TryFrom and handle conversion errors
            let template_id = tx.template_id.try_into().unwrap();
            let method = tx.method;
            let args = tx.args;
            let sender = RistrettoPublicKey::from_bytes(&tx.sender).unwrap();
            let instruction = Instruction::new(template_id, method, args, sender);

            Some(DomainMessage {
                source_peer: msg.source_peer.clone(),
                dht_header: msg.dht_header.clone(),
                authenticated_origin: msg.authenticated_origin.clone(),
                inner: instruction,
            })
        },
    }
}
