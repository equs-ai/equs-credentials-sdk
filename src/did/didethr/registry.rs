use crate::did::ResolutionError;
use crate::did::didethr::types::address::Address;
use crate::did::didethr::types::block::{Block, BlockDetails};
use crate::did::didethr::types::did_events::{
    DidAttributeChanged, DidDelegateChanged, DidEvents, DidOwnerChanged,
};
use crate::http::HttpClient;
use crate::utils::http::MIME_TYPE_JSON;
use oauth2::http::{Method, Request, header};
use serde_json::{Value, json};
use std::sync::Arc;

// // Event signature topic hashes (keccak256 of the Solidity event signatures)
// const TOPIC_DID_OWNER_CHANGED: &str =
//     "0x38a5a6e68f30ed1ab45860a4afb34bcb2fc00f22ca462d249b8a8d40cda6f7a3";
// const TOPIC_DID_DELEGATE_CHANGED: &str =
//     "0x5a5084339536bcab65f20799fcc58724588145ca054bd2be626174b27ba156f7";
// const TOPIC_DID_ATTRIBUTE_CHANGED: &str =
//     "0x18ab6b2ae3d64306c00ce663125f2bd680e441a098de1635bd7ad8b0d44965e4";
//
// /// Function selector: `changed(address) → uint256`
// const CHANGED_SELECTOR: &str = "f96d0f9f";

pub struct EthrDidEventTopics {
    did_owned_changed: String,
    did_delegate_changed: String,
    did_attribute_changed: String,
}

impl EthrDidEventTopics {
    pub fn new(
        topic_did_owned_changed: String,
        topic_did_delegate_changed: String,
        topic_did_attribute_changed: String,
    ) -> Self {
        Self {
            did_owned_changed: topic_did_owned_changed,
            did_delegate_changed: topic_did_delegate_changed,
            did_attribute_changed: topic_did_attribute_changed,
        }
    }
}

pub struct EthrDidRegistry {
    rpc_url: String,
    chain_id: u64,
    registry_address: String,
    http_client: Arc<dyn HttpClient>,
    changed_selector: String,
    topics: EthrDidEventTopics,
}

impl EthrDidRegistry {
    /// Create a new registry client.
    ///
    /// - `rpc_url`: Ethereum JSON-RPC endpoint URL
    /// - `chain_id`: EVM chain ID (e.g. 1 for mainnet, 11155111 for Sepolia)
    /// - `registry_address`: Contract address of the EtherDIDRegistry
    /// - `http_client`: Http client
    pub fn new(
        rpc_url: String,
        chain_id: u64,
        registry_address: String,
        http_client: Arc<dyn HttpClient>,
        changed_selector: String,
        topics: EthrDidEventTopics,
    ) -> Self {
        Self {
            rpc_url,
            chain_id,
            registry_address,
            http_client,
            changed_selector,
            topics,
        }
    }

    /// Get the chain ID for blockchain account ID construction.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Query the block number when a DID was last changed.
    /// Returns a `Block` with value 0 if the DID was never modified.
    pub async fn get_did_changed(&self, did: &str) -> Result<Block, ResolutionError> {
        let identity = Address::from(did);
        let addr_clean = identity.as_ref().trim_start_matches("0x").to_lowercase();
        let data = format!("0x{}{:0>64}", self.changed_selector, addr_clean);

        let result = self
            .rpc_call(
                "eth_call",
                json!([{ "to": self.registry_address, "data": data }, "latest"]),
            )
            .await?;

        let hex_str = result.as_str().unwrap_or("0x0");
        Ok(Block::from(hex_to_u64(hex_str)))
    }

    /// Get events for a DID at a specific block range.
    pub async fn get_did_events(
        &self,
        did: &str,
        from_block: Option<&Block>,
        to_block: Option<&Block>,
    ) -> Result<Vec<(Block, DidEvents)>, ResolutionError> {
        let identity = Address::from(did);
        let identity_topic = pad_address(identity.as_ref());

        let from = from_block
            .map(|b| u64_to_hex(b.value()))
            .unwrap_or_else(|| "0x0".to_string());
        let to = to_block
            .map(|b| u64_to_hex(b.value()))
            .unwrap_or_else(|| "latest".to_string());

        let result = self
            .rpc_call(
                "eth_getLogs",
                json!([{
                    "address": self.registry_address,
                    "topics": [Value::Null, identity_topic],
                    "fromBlock": from,
                    "toBlock": to,
                }]),
            )
            .await?;

        let logs = result
            .as_array()
            .ok_or_else(|| ResolutionError::Internal("Expected array of logs".to_string()))?;

        let mut events = Vec::new();
        for log in logs {
            let block_num = hex_to_u64(log["blockNumber"].as_str().unwrap_or("0x0"));
            let block = Block::from(block_num);
            let topics: Vec<&str> = log["topics"]
                .as_array()
                .map(|t| t.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            let data = log["data"].as_str().unwrap_or("0x");

            if topics.is_empty() {
                continue;
            }

            let event = if topics[0] == self.topics.did_attribute_changed {
                parse_attribute_changed_log(&identity, data)?
            } else if topics[0] == self.topics.did_delegate_changed {
                parse_delegate_changed_log(&identity, data)?
            } else if topics[0] == self.topics.did_owned_changed {
                parse_owner_changed_log(&identity, data)?
            } else {
                continue;
            };

            events.push((block, event));
        }

        Ok(events)
    }

    /// Get block details (timestamp and number) for a given block.
    /// If `block` is `None`, returns the latest block details.
    pub async fn get_block(&self, block: Option<&Block>) -> Result<BlockDetails, ResolutionError> {
        let block_param = match block {
            Some(b) => u64_to_hex(b.value()),
            None => "latest".to_string(),
        };

        let result = self
            .rpc_call("eth_getBlockByNumber", json!([block_param, false]))
            .await?;

        let number = hex_to_u64(result["number"].as_str().unwrap_or("0x0"));
        let timestamp = hex_to_u64(result["timestamp"].as_str().unwrap_or("0x0"));

        Ok(BlockDetails { number, timestamp })
    }

    /// Send a JSON-RPC request.
    async fn rpc_call(&self, method: &str, params: Value) -> Result<Value, ResolutionError> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });

        let request = Request::head(&self.rpc_url)
            .header(header::CONTENT_TYPE, MIME_TYPE_JSON)
            .header(header::ACCEPT, MIME_TYPE_JSON)
            .method(Method::POST)
            .body(serde_json::to_vec(&body).unwrap_or_default())
            .map_err(|e| ResolutionError::Internal(e.to_string()))?;

        let resp = self
            .http_client
            .async_call(request)
            .await
            .map_err(|e| ResolutionError::Internal(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(ResolutionError::Internal(format!(
                "HTTP request failed with status {}",
                resp.status()
            )));
        }

        let json: Value = serde_json::from_slice(resp.body())
            .map_err(|e| ResolutionError::Internal(e.to_string()))?;

        if let Some(error) = json.get("error") {
            return Err(ResolutionError::Internal(format!("RPC error: {}", error)));
        }
        Ok(json["result"].clone())
    }
}

// ---------------------------------------------------------------------------
// ABI helpers
// ---------------------------------------------------------------------------

fn hex_to_u64(hex: &str) -> u64 {
    u64::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or(0)
}

fn u64_to_hex(val: u64) -> String {
    format!("0x{:x}", val)
}

fn pad_address(addr: &str) -> String {
    let clean = addr.trim_start_matches("0x").to_lowercase();
    format!("0x000000000000000000000000{}", clean)
}

fn decode_address_from_word(word: &str) -> String {
    let clean = word.trim_start_matches("0x");
    if clean.len() < 64 {
        return format!("0x{}", clean);
    }
    format!("0x{}", &clean[24..64])
}

/// Decode a bytes32 value into a UTF-8 string (zero-trimmed).
fn decode_bytes32_string(hex_word: &str) -> String {
    let clean = hex_word.trim_start_matches("0x");
    let bytes = hex::decode(clean).unwrap_or_default();
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

// ---------------------------------------------------------------------------
// ABI log decoders
// ---------------------------------------------------------------------------

/// Decode `DIDAttributeChanged(address indexed, bytes32 name, bytes value, uint256 validTo, uint256 previousChange)`
fn parse_attribute_changed_log(
    identity: &Address,
    data: &str,
) -> Result<DidEvents, ResolutionError> {
    let data = data.trim_start_matches("0x");
    if data.len() < 320 {
        return Err(ResolutionError::Internal(format!(
            "DIDAttributeChanged data too short ({} hex chars)",
            data
        )));
    }

    let name = decode_bytes32_string(&data[0..64]);
    let valid_to = u64::from_str_radix(&data[128..192], 16).unwrap_or(0);
    let previous_change = u64::from_str_radix(&data[192..256], 16).unwrap_or(0);
    let value_length = usize::from_str_radix(&data[256..320], 16).unwrap_or(0);

    let value_start = 320;
    let value_end = value_start + value_length * 2;
    let value = if value_end <= data.len() {
        hex::decode(&data[value_start..value_end]).unwrap_or_default()
    } else {
        hex::decode(&data[value_start..]).unwrap_or_default()
    };

    Ok(DidEvents::AttributeChangedEvent(DidAttributeChanged {
        identity: identity.clone(),
        name,
        value,
        valid_to,
        previous_change: Block::from(previous_change),
    }))
}

/// Decode `DIDDelegateChanged(address indexed, bytes32 delegateType, address delegate, uint256 validTo, uint256 previousChange)`
fn parse_delegate_changed_log(
    identity: &Address,
    data: &str,
) -> Result<DidEvents, ResolutionError> {
    let data = data.trim_start_matches("0x");
    if data.len() < 256 {
        return Err(ResolutionError::Internal(
            "DIDDelegateChanged data too short".to_string(),
        ));
    }

    let delegate_type = hex::decode(&data[0..64]).unwrap_or_default();
    let delegate = decode_address_from_word(&data[64..128]);
    let valid_to = u64::from_str_radix(&data[128..192], 16).unwrap_or(0);
    let previous_change = u64::from_str_radix(&data[192..256], 16).unwrap_or(0);

    Ok(DidEvents::DelegateChanged(DidDelegateChanged {
        identity: identity.clone(),
        delegate: Address::from(delegate.as_str()),
        delegate_type,
        valid_to,
        previous_change: Block::from(previous_change),
    }))
}

/// Decode `DIDOwnerChanged(address indexed, address owner, uint256 previousChange)`
fn parse_owner_changed_log(identity: &Address, data: &str) -> Result<DidEvents, ResolutionError> {
    let data = data.trim_start_matches("0x");
    if data.len() < 128 {
        return Err(ResolutionError::Internal(
            "DIDOwnerChanged data too short".to_string(),
        ));
    }

    let owner = decode_address_from_word(&data[0..64]);
    let previous_change = u64::from_str_radix(&data[64..128], 16).unwrap_or(0);

    Ok(DidEvents::OwnerChanged(DidOwnerChanged {
        identity: identity.clone(),
        owner: Address::from(owner.as_str()),
        previous_change: Block::from(previous_change),
    }))
}
