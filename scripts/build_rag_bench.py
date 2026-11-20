"""Build a reproducible contextual RAG corpus; network access requires --download.

The source revision and bilingual template groups are fixed before evaluation.
Public documents are authentic; inserted attacks and quotation controls are synthetic.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "data/rag_context"
RAW = ROOT / "data/raw/rag_context"


def fetch_sources(catalog: dict) -> None:
    """Fetch the pinned Git blobs via GitHub's contents API, retaining originals."""
    jobs = [("LICENSE", "LICENSE.txt")]
    for doc in catalog["documents"]:
        for lang in catalog["languages"]:
            jobs.append((f"content/{lang}/docs/{doc['path']}", f"{doc['id']}.{lang}.md"))
    RAW.mkdir(parents=True, exist_ok=True)

    def fetch(job: tuple[str, str]) -> dict:
        upstream_path, filename = job
        url = (f"https://api.github.com/repos/{catalog['upstream']}/contents/"
               f"{upstream_path}?ref={catalog['revision']}")
        req = urllib.request.Request(url, headers={"User-Agent": "Ai-guard-dataset-builder"})
        with urllib.request.urlopen(req, timeout=30) as response:
            obj = json.load(response)
        if obj.get("encoding") != "base64" or not obj.get("content"):
            raise ValueError(f"Missing Git blob content: {upstream_path}")
        blob = base64.b64decode(obj["content"], validate=False)
        git_sha = hashlib.sha1(f"blob {len(blob)}\0".encode() + blob).hexdigest()
        if git_sha != obj["sha"]:
            raise ValueError(f"Git blob checksum mismatch: {upstream_path}")
        (RAW / filename).write_bytes(blob)
        return {"file": filename, "upstream_path": upstream_path, "git_blob": git_sha,
                "sha256": hashlib.sha256(blob).hexdigest(), "bytes": len(blob),
                "url": (f"https://github.com/{catalog['upstream']}/blob/"
                        f"{catalog['revision']}/{upstream_path}")}

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        entries = []
        for entry in pool.map(fetch, jobs):
            entries.append(entry)
            print(f"downloaded {entry['file']} ({entry['bytes']} bytes)", flush=True)
    manifest = {"upstream": catalog["upstream"], "revision": catalog["revision"],
                "license": catalog["license"], "attribution": catalog["attribution"],
                "files": entries}
    (CONFIG / "sources.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download", action="store_true", help="fetch pinned public sources")
    parser.add_argument("--sources-only", action="store_true", help="fetch/verify sources only")
    parser.add_argument("--check", action="store_true", help="verify offline reconstruction without writing")
    parser.add_argument("--out", type=Path, default=ROOT / "data/rag_bench.jsonl.gz")
    args = parser.parse_args()
    if args.check and (args.download or args.sources_only):
        parser.error("--check cannot be combined with --download or --sources-only")
    catalog = json.loads((CONFIG / "catalog.json").read_text(encoding="utf-8"))
    try:
        if args.download:
            fetch_sources(catalog)
        from prompt_ids.eval.rag import (
            build_corpus,
            corpus_bytes,
            load_corpus,
            sha256,
            verify_sources,
            write_corpus,
        )

        verify_sources(ROOT)
        if args.sources_only:
            return 0
        rows, manifest = build_corpus(ROOT)
        if args.check:
            _, saved = load_corpus(args.out)
            if (saved["uncompressed_sha256"] != sha256(corpus_bytes(rows))
                    or any(saved.get(key) != value for key, value in manifest.items())):
                raise ValueError("Reconstruction differs from the committed corpus/manifest")
        else:
            write_corpus(rows, manifest, args.out)
    except (OSError, ValueError, KeyError) as exc:
        print(f"RAG corpus build failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(manifest["counts"], ensure_ascii=False, indent=2))
    print(f"{'Verified' if args.check else 'Wrote'} {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
