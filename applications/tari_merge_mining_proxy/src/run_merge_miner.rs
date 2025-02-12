// Copyright 2020. The Tari Project
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

use std::convert::Infallible;

use futures::future;
use hyper::{service::make_service_fn, Server};
use log::*;
use tari_base_node_grpc_client::BaseNodeGrpcClient;
use tari_common::{
    configuration::bootstrap::{grpc_default_port, ApplicationType},
    load_configuration,
    DefaultConfigLoader,
};
use tari_comms::utils::multiaddr::multiaddr_to_socketaddr;
use tari_core::proof_of_work::randomx_factory::RandomXFactory;
use tari_wallet_grpc_client::WalletGrpcClient;
use tokio::time::Duration;

use crate::{
    block_template_data::BlockTemplateRepository,
    config::MergeMiningProxyConfig,
    error::MmProxyError,
    proxy::MergeMiningProxyService,
    Cli,
};
const LOG_TARGET: &str = "tari_mm_proxy::proxy";

pub async fn start_merge_miner(cli: Cli) -> Result<(), anyhow::Error> {
    let config_path = cli.common.config_path();
    let cfg = load_configuration(&config_path, true, &cli)?;
    let mut config = MergeMiningProxyConfig::load_from(&cfg)?;
    setup_grpc_config(&mut config);

    info!(target: LOG_TARGET, "Configuration: {:?}", config);
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(25)
        .build()
        .map_err(MmProxyError::ReqwestError)?;

    let base_node = multiaddr_to_socketaddr(
        config
            .base_node_grpc_address
            .as_ref()
            .expect("No base node address provided"),
    )?;
    info!(target: LOG_TARGET, "Connecting to base node at {}", base_node);
    println!("Connecting to base node at {}", base_node);
    let base_node_client = BaseNodeGrpcClient::connect(format!("http://{}", base_node)).await?;
    let wallet_addr = multiaddr_to_socketaddr(
        config
            .console_wallet_grpc_address
            .as_ref()
            .expect("No waller address provided"),
    )?;
    info!(target: LOG_TARGET, "Connecting to wallet at {}", wallet_addr);
    let wallet_addr = format!("http://{}", wallet_addr);
    let wallet_client =
        WalletGrpcClient::connect_with_auth(&wallet_addr, &config.console_wallet_grpc_authentication).await?;
    let listen_addr = multiaddr_to_socketaddr(&config.listener_address)?;
    let randomx_factory = RandomXFactory::new(config.max_randomx_vms);
    let xmrig_service = MergeMiningProxyService::new(
        config,
        client,
        base_node_client,
        wallet_client,
        BlockTemplateRepository::new(),
        randomx_factory,
    );
    let service = make_service_fn(|_conn| future::ready(Result::<_, Infallible>::Ok(xmrig_service.clone())));

    match Server::try_bind(&listen_addr) {
        Ok(builder) => {
            info!(target: LOG_TARGET, "Listening on {}...", listen_addr);
            println!("Listening on {}...", listen_addr);
            builder.serve(service).await?;
            Ok(())
        },
        Err(err) => {
            error!(target: LOG_TARGET, "Fatal: Cannot bind to '{}'.", listen_addr);
            println!("Fatal: Cannot bind to '{}'.", listen_addr);
            println!("It may be part of a Port Exclusion Range. Please try to use another port for the");
            println!("'proxy_host_address' in 'config/config.toml' and for the applicable XMRig '[pools][url]' or");
            println!("[pools][self-select]' config setting that can be found  in 'config/xmrig_config_***.json' or");
            println!("'<xmrig folder>/config.json'.");
            println!();
            Err(err.into())
        },
    }
}

fn setup_grpc_config(config: &mut MergeMiningProxyConfig) {
    if config.base_node_grpc_address.is_none() {
        config.base_node_grpc_address = Some(
            format!(
                "/ip4/127.0.0.1/tcp/{}",
                grpc_default_port(ApplicationType::BaseNode, config.network)
            )
            .parse()
            .unwrap(),
        );
    }

    if config.console_wallet_grpc_address.is_none() {
        config.console_wallet_grpc_address = Some(
            format!(
                "/ip4/127.0.0.1/tcp/{}",
                grpc_default_port(ApplicationType::ConsoleWallet, config.network)
            )
            .parse()
            .unwrap(),
        );
    }
}
