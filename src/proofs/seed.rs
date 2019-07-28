use serde::{Deserialize, Serialize};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use blake2::crypto_mac::Mac;
use blake2::Blake2b;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Seed {
    pub timestamp: i32,
    pub seed: String,
}

pub fn get_seed() -> Seed {
    // Get current timestamp
    let ts = {
        let start = SystemTime::now();
        let timestamp = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        timestamp.as_secs() as i32
    };

    // take the mac of the timestamp
    let key = env::var("LDC_KEY").unwrap_or_else(|_| "my key".into());
    let mut hasher = Blake2b::new_varkey(key.as_bytes()).unwrap();
    hasher.input(format!("{}", ts).as_bytes());
    let result = hasher.result();
    let code_bytes = result.code().to_vec();

    Seed {
        timestamp: ts,
        seed: hex::encode(&code_bytes),
    }
}
