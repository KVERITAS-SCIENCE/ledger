"""Record the K-Veritas ledger checkpoint here when the ledger has grown, after checking
it is signed by a K-Veritas key and that the ledger still holds the last one recorded."""

import base64
import json
import os
import re
import sys
import urllib.request
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

API = "https://kveritas.org/api/ledger"


def get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=60) as resp:
        return json.load(resp)


def when(t: str) -> datetime:
    return datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", t.replace(" ", "T", 1).replace("Z", "+00:00")))


def trusted_at(key: dict, at: str) -> bool:
    if key["status"] in ("active", "next"):
        return True
    return key["status"] == "retired" and (not key.get("until") or when(at) <= when(key["until"]))


def signed(cp: dict) -> bool:
    payload = f"kveritas-ledger-checkpoint:{cp['seq']}:{cp['entry_hash']}:{cp['at']}".encode()
    for k in json.load(open("trusted_keys.json"))["keys"]:
        if not trusted_at(k, cp["at"]):
            continue
        try:
            serialization.load_pem_public_key(k["public_key_pem"].encode()).verify(
                base64.b64decode(cp["signature"]), payload,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except Exception:
            continue
    return False


def main() -> None:
    cp = get(f"{API}/checkpoint")
    if not signed(cp):
        sys.exit("checkpoint is not signed by a K-Veritas key")
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
