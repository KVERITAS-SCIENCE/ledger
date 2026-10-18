"""Record the K-Veritas ledger checkpoint here when the ledger has grown, after checking
it is signed by the K-Veritas key and that the ledger still holds the last one recorded."""

import base64
import json
import os
import sys
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

API = "https://kveritas.org/api/ledger"


def get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=60) as resp:
        return json.load(resp)


def signed(cp: dict, key) -> bool:
    payload = f"kveritas-ledger-checkpoint:{cp['seq']}:{cp['entry_hash']}:{cp['at']}".encode()
    try:
        key.verify(base64.b64decode(cp["signature"]), payload,
                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                   hashes.SHA256())
        return True
    except Exception:
        return False


def main() -> None:
    key = serialization.load_pem_public_key(open("public_key.pem", "rb").read())
    cp = get(f"{API}/checkpoint")
    if not signed(cp, key):
        sys.exit("checkpoint is not signed by the K-Veritas key")
    if os.path.exists("checkpoint.json"):
        prev = json.load(open("checkpoint.json"))
        check = get(f"{API}/consistent?seq={prev['seq']}&entry_hash={prev['entry_hash']}")
        if not check["consistent"]:
            sys.exit(f"ledger truncated: {check['reason']}")
        if cp["seq"] == prev["seq"]:
            print(f"no new entries since #{prev['seq']}")
            return
    with open("checkpoint.json", "w") as f:
        f.write(json.dumps(cp, indent=2) + "\n")
    with open("checkpoints.jsonl", "a") as f:
        f.write(json.dumps(cp) + "\n")
    print(f"checkpoint at entry #{cp['seq']}")


if __name__ == "__main__":
    main()
