use std::sync::Arc;

use async_trait::async_trait;
use tari_comms_dht::Dht;
use tari_dan_core::services::mempool::service::MempoolServiceHandle;
use tari_p2p::comms_connector::SubscriptionFactory;
use tari_service_framework::{ServiceInitializationError, ServiceInitializer, ServiceInitializerContext};

use super::{inbound::TariCommsMempoolInboundHandle, outbound::TariCommsMempoolOutboundService};

pub struct MempoolInitializer {
    mempool: MempoolServiceHandle,
    inbound_message_subscription_factory: Arc<SubscriptionFactory>,
}

impl MempoolInitializer {
    pub fn new(mempool: MempoolServiceHandle, inbound_message_subscription_factory: Arc<SubscriptionFactory>) -> Self {
        Self {
            mempool,
            inbound_message_subscription_factory,
        }
    }
}

#[async_trait]
impl ServiceInitializer for MempoolInitializer {
    async fn initialize(&mut self, context: ServiceInitializerContext) -> Result<(), ServiceInitializationError> {
        let mut mempool_service = self.mempool.clone();
        let mut mempool_inbound = TariCommsMempoolInboundHandle::new(
            self.inbound_message_subscription_factory.clone(),
            mempool_service.clone(),
        );
        context.register_handle(mempool_inbound.clone());

        context.spawn_until_shutdown(move |handles| async move {
            let dht = handles.expect_handle::<Dht>();
            let outbound_requester = dht.outbound_requester();
            let mempool_outbound = TariCommsMempoolOutboundService::new(outbound_requester);
            mempool_service.set_outbound_service(Box::new(mempool_outbound)).await;

            mempool_inbound.run().await;
        });

        Ok(())
    }
}
