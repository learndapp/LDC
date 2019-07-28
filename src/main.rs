use clap::{value_t, App, AppSettings, Arg, SubCommand};

use ldc::proofs::all::*;
use ldc::proofs::proof;
use ldc::proofs::seed::get_seed;

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let matches = App::new(stringify!("Replication Game CLI"))
        .version("0.1.0")
        .arg(
            Arg::with_name("size")
                .long("size")
                .default_value("0")
                .help("The data size in KB")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("degree")
                .help("The degree")
                .long("degree")
                .default_value("6")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("vde")
                .help("The VDE difficulty")
                .long("vde")
                .default_value("0")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("expansion-degree")
                .help("The expansion degree for Zigzag")
                .long("expansion-degree")
                .default_value("6")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("layers")
                .help("The layers for Zigzag")
                .long("layers")
                .default_value("4")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("proof-path")
                .help("The proof.json path")
                .long("proof-path")
                .default_value("./proof.json")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("prover")
                .long("prover")
                .help("The prover name to use for the response")
                .default_value("")
                .takes_value(true),
        )
        .setting(AppSettings::SubcommandRequired)
        .subcommand(SubCommand::with_name("drgporep"))
        .subcommand(SubCommand::with_name("zigzag"))
        .subcommand(SubCommand::with_name("proof"))
        .get_matches();

    let seed = get_seed();

    // let seed = Seed {
    //     timestamp: value_t!(matches, "timestamp", i32).unwrap(),
    //     seed: value_t!(matches, "seed", String).unwrap(),
    // };

    let (typ, zigzag) = match matches.subcommand().0 {
        "drgporep" => (proof::ProofType::DrgPoRep, None),
        "zigzag" => (
            proof::ProofType::Zigzag,
            Some(proof::ZigZagParams {
                expansion_degree: value_t!(matches, "expansion-degree", usize).unwrap(),
                layers: value_t!(matches, "layers", usize).unwrap(),
                is_tapered: true,
                taper_layers: 7,
                taper: 1.0 / 3.0,
            }),
        ),
        "proof" => (proof::ProofType::Proof, None),
        _ => panic!("invalid subcommand: {}", matches.subcommand().0),
    };

    let params = proof::Params {
        typ: typ.clone(),
        size: value_t!(matches, "size", usize).unwrap() * 1024,
        degree: value_t!(matches, "degree", usize).unwrap(),
        vde: value_t!(matches, "vde", usize).unwrap(),
        challenge_count: 200,
        zigzag,
    };

    let prover = value_t!(matches, "prover", String).unwrap();

    let proof_path = value_t!(matches, "proof-path", String).unwrap();

    let start = SystemTime::now();
    let start_time = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    let res = match typ {
        proof::ProofType::DrgPoRep => porep_work(prover, params, seed),
        proof::ProofType::Zigzag => zigzag_work(prover, params, seed),
        proof::ProofType::Proof => v_proof(proof_path),
    };
    
    let end = SystemTime::now();
    let end_time = end
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    eprintln!(
        "duration: {:?}(secs)",
        end_time.as_secs() - start_time.as_secs()
    );

    println!("{}", res);
}
