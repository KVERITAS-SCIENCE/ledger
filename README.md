# K-Veritas ledger checkpoints

Signed snapshots of the [K-Veritas](https://kveritas.org) transparency ledger, kept outside its server.

## What

- `checkpoint.json`: the newest checkpoint. Entry number, entry hash, time, server signature.
- `checkpoints.jsonl`: every checkpoint recorded, oldest first.
- `public_key.pem`: the K-Veritas server key the signatures verify against.

Recorded hourly by a GitHub Action, only when the ledger has grown.

## Why

The ledger is a hash chain, so no entry can be changed or removed from the middle undetected. Entries cut from the end would leave a shorter chain that still checks out. A checkpoint recorded here proves the ledger once held that entry; if it later does not, anyone can see it.

The Action refuses to record a checkpoint, and fails, when the ledger no longer holds the last one recorded here.

## Check

```bash
curl -s "https://kveritas.org/api/ledger/consistent?seq=<seq>&entry_hash=<entry_hash>"
```

Signature payload: `kveritas-ledger-checkpoint:<seq>:<entry_hash>:<at>`, RSA-PSS-SHA256.
