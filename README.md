# LDC - Learn Dapp Common
Blockchain for LearnDapp, explore the practical Dapp together.

## proof
From the LDC/ directory, compile the binary:

```bash
cargo +nightly build
```

Generate proof:
```bash
./target/debug/ldc --size 1024 --prover lduser zigzag > proof.json
```

Validate proof:
```bash
./target/debug/ldc --proof-path ./proof.json proof
```
