"""Fetch the open-licensed training sets for the injection classifier (ticket 10) into train/out/public.jsonl.

Rows come from the Hugging Face datasets-server; the dataset revision (sha) seen at fetch time, the licence and the
sha256 of the written file go to train/out/public.provenance.json (spec §9.3: source, licence, version, hash).
Never the holdout: deepset's *test* split is in data/eval/v1, so only its train split is used here, and the trainer
drops any text that also occurs in the holdout.
"""

import hashlib
import json
import random
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

OUT = Path(__file__).parent / "out"

# (dataset, split, licence, max rows, row -> (text, attack) or None)
SOURCES = [
    (
        "deepset/prompt-injections",
        "train",
        "Apache-2.0",
        None,
        lambda r: (r["text"], r["label"] == 1),
    ),
    (
        "jackhhao/jailbreak-classification",
        "train",
        "Apache-2.0",
        None,
        lambda r: (r["prompt"], r["type"] == "jailbreak"),
    ),
    (
        "reshabhs/SPML_Chatbot_Prompt_Injection",
        "train",
        "MIT",
        4000,
        lambda r: (r["User Prompt"], r["Prompt injection"] == 1),
    ),
    (
        "cahya/alpaca-id-cleaned",
        "train",
        "CC-BY-4.0",
        3000,
        lambda r: ((r["instruction"] + "\n" + (r.get("input") or "")).strip(), False),
    ),
]


def get(url):
    for attempt in range(10):
        try:
            time.sleep(0.5)  # the datasets-server rate-limits anonymous clients
            # nosemgrep: dynamic-urllib-use-detected -- fixed HuggingFace URLs, offline training
            return json.load(urllib.request.urlopen(url, timeout=60))
        except Exception:
            if attempt == 9:
                raise
            time.sleep(5 * (attempt + 1))


def rows(dataset, split, limit):
    base = "https://datasets-server.huggingface.co/rows?"
    info = get(
        "https://datasets-server.huggingface.co/splits?dataset="
        + urllib.parse.quote(dataset)
    )
    config = next(s["config"] for s in info["splits"] if s["split"] == split)
    total = get(
        base
        + urllib.parse.urlencode(
            {
                "dataset": dataset,
                "config": config,
                "split": split,
                "offset": 0,
                "length": 1,
            }
        )
    )["num_rows_total"]
    offsets = list(range(0, total, 100))
    if limit:
        random.Random(13).shuffle(offsets)
        offsets = offsets[: (limit + 99) // 100]
    for off in offsets:
        q = {
            "dataset": dataset,
            "config": config,
            "split": split,
            "offset": off,
            "length": 100,
        }
        for r in get(base + urllib.parse.urlencode(q))["rows"]:
            yield r["row"]


def main():
    OUT.mkdir(exist_ok=True)
    prov, n = [], 0
    with open(OUT / "public.jsonl", "w") as f:
        for ds, split, lic, limit, conv in SOURCES:
            sha = get("https://huggingface.co/api/datasets/" + ds)["sha"]
            k = 0
            for r in rows(ds, split, limit):
                text, attack = conv(r)
                if not text or not text.strip():
                    continue
                f.write(
                    json.dumps(
                        {"text": text, "attack": bool(attack), "source": ds},
                        ensure_ascii=False,
                    )
                    + "\n"
                )
                k += 1
            prov.append(
                {
                    "dataset": ds,
                    "split": split,
                    "license": lic,
                    "revision": sha,
                    "rows": k,
                }
            )
            n += k
            print(ds, k, file=sys.stderr)
    digest = hashlib.sha256((OUT / "public.jsonl").read_bytes()).hexdigest()
    (OUT / "public.provenance.json").write_text(
        json.dumps({"sources": prov, "rows": n, "sha256": digest}, indent=1)
    )
    print(digest, n)


if __name__ == "__main__":
    main()
