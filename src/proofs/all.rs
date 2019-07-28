use std::env;
use std::fs::File;
use std::io::Write;

use blake2::crypto_mac::Mac;
use blake2::Blake2b;

use memmap::MmapMut;
use memmap::MmapOptions;
use paired::bls12_381::Bls12;
use rand::{thread_rng, Rng};

use storage_proofs::drgporep::{self, *};
use storage_proofs::drgraph::*;
use storage_proofs::fr32::fr_into_bytes;
use storage_proofs::hasher::{Domain, Hasher, PedersenHasher};
use storage_proofs::layered_drgporep::{self, LayerChallenges};
use storage_proofs::porep::PoRep;
use storage_proofs::proof::ProofScheme;
use storage_proofs::zigzag_drgporep::*;

use crate::proofs::proof;
use crate::proofs::seed::Seed;

fn file_backed_mmap_from_random_bytes(rng: &mut impl Rng, n: usize) -> MmapMut {
    let mut tmpfile: File = tempfile::tempfile().unwrap();

    for _ in 0..n {
        tmpfile
            .write_all(&fr_into_bytes::<Bls12>(&rng.gen()))
            .unwrap();
    }

    unsafe { MmapOptions::new().map_mut(&tmpfile).unwrap() }
}

pub fn zigzag_work(prover: String, params: proof::Params, seed: Seed) -> String {
    let replica_id = id_from_str::<<PedersenHasher as Hasher>::Domain>(&seed.seed);

    let data_size = params.size;
    let m = params.degree;
    let challenge_count = params.challenge_count;
    let sloth_iter = params.vde;

    let (expansion_degree, layer_challenges) = params
        .as_zigzag_params()
        .unwrap_or_else(|| (6, LayerChallenges::new_fixed(10, challenge_count)));

    let partitions = 1;

    let mut rng = thread_rng();

    eprintln!("generating fake data");

    let nodes = data_size / 32;
    let mut data = file_backed_mmap_from_random_bytes(&mut rng, nodes);

    let sp = layered_drgporep::SetupParams {
        drg: drgporep::DrgParams {
            nodes,
            degree: m,
            expansion_degree,
            // TODO: where should this come from?
            seed: [0u32; 7],
        },
        sloth_iter,
        layer_challenges,
    };

    eprintln!("running setup");
    let pp = ZigZagDrgPoRep::<PedersenHasher>::setup(&sp).unwrap();

    eprintln!("running replicate");

    let (tau, aux) =
        ZigZagDrgPoRep::<PedersenHasher>::replicate(&pp, &replica_id, &mut data, None).unwrap();

    let pub_inputs = layered_drgporep::PublicInputs::<<PedersenHasher as Hasher>::Domain> {
        replica_id,
        tau: Some(tau.simplify()),
        comm_r_star: tau.comm_r_star,
        k: Some(0),
    };

    let priv_inputs = layered_drgporep::PrivateInputs {
        aux,
        tau: tau.layer_taus.clone(),
    };

    eprintln!("generating one proof");

    let pr = ZigZagDrgPoRep::<PedersenHasher>::prove_all_partitions(
        &pp,
        &pub_inputs,
        &priv_inputs,
        partitions,
    )
    .expect("failed to prove");

    let verified = ZigZagDrgPoRep::<PedersenHasher>::verify_all_partitions(&pp, &pub_inputs, &pr)
        .expect("failed to verify");

    assert!(verified, "verification failed");

    serde_json::to_string(&proof::Response {
        prover,
        seed,
        proof_params: params,
        proof: proof::Proof::Zigzag(pr),
        comm_r_star: Some(tau.comm_r_star),
        tau: tau.simplify(),
    })
    .expect("failed to serialize")
}

pub fn id_from_str<T: Domain>(raw: &str) -> T {
    let replica_id_raw = hex::decode(raw).expect("invalid hex for replica id seed");
    let mut replica_id_bytes = vec![0u8; 32];
    let len = ::std::cmp::min(32, replica_id_raw.len());
    replica_id_bytes[..len].copy_from_slice(&replica_id_raw[..len]);
    T::try_from_bytes(&replica_id_bytes).expect("invalid replica id")
}

pub fn porep_work(prover: String, params: proof::Params, seed: Seed) -> String {
    let replica_id = id_from_str::<<PedersenHasher as Hasher>::Domain>(&seed.seed);

    let data_size = params.size;
    let m = params.degree;
    let sloth_iter = params.vde;
    let challenge_count = params.challenge_count;

    let mut rng = thread_rng();

    eprintln!("generating fake data");

    let nodes = data_size / 32;

    let mut data: Vec<u8> = (0..nodes)
        .flat_map(|_| fr_into_bytes::<Bls12>(&rng.gen()))
        .collect();

    // TODO: proper challenge generation
    let challenges = vec![2; challenge_count];

    let sp = SetupParams {
        drg: DrgParams {
            nodes,
            degree: m,
            expansion_degree: 0,
            // TODO: where should this come from?
            seed: [0u32; 7],
        },
        challenges_count: challenge_count,
        private: false,
        sloth_iter,
    };

    eprintln!("running setup");
    let pp = DrgPoRep::<PedersenHasher, BucketGraph<PedersenHasher>>::setup(&sp).unwrap();

    eprintln!("running replicate");
    let (tau, aux) =
        DrgPoRep::<PedersenHasher, _>::replicate(&pp, &replica_id, data.as_mut_slice(), None)
            .unwrap();

    let pub_inputs = PublicInputs {
        replica_id: Some(replica_id),
        challenges,
        tau: Some(tau),
    };

    let priv_inputs = PrivateInputs::<PedersenHasher> {
        tree_d: &aux.tree_d,
        tree_r: &aux.tree_r,
    };

    eprintln!("sampling proving & verifying");

    let pr = DrgPoRep::<PedersenHasher, _>::prove(&pp, &pub_inputs, &priv_inputs)
        .expect("failed to prove");

    DrgPoRep::<PedersenHasher, _>::verify(&pp, &pub_inputs, &pr).expect("failed to verify");

    serde_json::to_string(&proof::Response {
        prover,
        seed,
        proof_params: params,
        proof: proof::Proof::DrgPoRep(pr),
        comm_r_star: None,
        tau,
    })
    .expect("failed to serialize")
}

fn validate(res: &proof::Response) -> bool {
    let replica_id = id_from_str::<<PedersenHasher as Hasher>::Domain>(&res.seed.seed);
    let params = &res.proof_params;
    let data_size = params.size;
    let m = params.degree;
    let sloth_iter = params.vde;
    let challenge_count = params.challenge_count;
    let nodes = data_size / 32;
    let param_seed = [0u32; 7];

    match res.proof {
        proof::Proof::Zigzag(ref proof) => {
            if params.zigzag.is_none() {
                return false;
            }

            let (expansion_degree, layer_challenges) =
                params.as_zigzag_params().expect("missing zigzag params");
            let comm_r_star = res.comm_r_star.expect("missing comm r star");

            let sp = layered_drgporep::SetupParams {
                drg: drgporep::DrgParams {
                    nodes,
                    degree: m,
                    expansion_degree,
                    seed: param_seed,
                },
                sloth_iter,
                layer_challenges,
            };

            let pp = ZigZagDrgPoRep::<PedersenHasher>::setup(&sp).unwrap();

            let pub_inputs = layered_drgporep::PublicInputs::<<PedersenHasher as Hasher>::Domain> {
                replica_id,
                tau: Some(res.tau),
                comm_r_star,
                k: Some(0),
            };

            ZigZagDrgPoRep::<PedersenHasher>::verify_all_partitions(&pp, &pub_inputs, proof)
                .unwrap_or_else(|_| false)
        }
        proof::Proof::DrgPoRep(ref proof) => {
            let sp = SetupParams {
                drg: DrgParams {
                    nodes,
                    degree: m,
                    expansion_degree: 0,
                    seed: param_seed,
                },
                challenges_count: challenge_count,
                private: false,
                sloth_iter,
            };

            println!("running setup");
            let pp = DrgPoRep::<PedersenHasher, BucketGraph<PedersenHasher>>::setup(&sp).unwrap();
            let pub_inputs = PublicInputs::<<PedersenHasher as Hasher>::Domain> {
                replica_id: Some(replica_id),
                challenges: vec![2; challenge_count],
                tau: Some(res.tau),
            };

            DrgPoRep::<PedersenHasher, _>::verify(&pp, &pub_inputs, proof).unwrap_or_else(|_| false)
        }
    }
}

pub fn v_proof(proof_path: String) -> String {
    let file = File::open(proof_path).unwrap();

    let res: proof::Response = serde_json::from_reader(file).unwrap();

    println!("seed: {}\ntimestamp: {}", res.seed.seed, res.seed.timestamp);

    // Verify authenticity of seed
    let mac = hex::decode(&res.seed.seed).expect("invalid hex for replica id seed");
    let key = env::var("LDC_KEY").unwrap_or_else(|_| "my key".into());
    let mut hasher = Blake2b::new_varkey(key.as_bytes()).unwrap();
    hasher.input(&format!("{}", res.seed.timestamp).as_bytes());
    hasher.verify(&mac).unwrap();

    if !validate(&res) {
       return "proofs are invalid".to_string()
    }

    "success".to_string()
}
