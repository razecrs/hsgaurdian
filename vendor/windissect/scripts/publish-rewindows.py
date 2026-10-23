"""Publish windissect build records to the ReWindows archive.

One repo per module, matching the existing convention. The point of the archive
is a history of builds over time, so each push adds build records rather than
replacing them.

IR is gzipped. A full-depth record for a shell binary runs to hundreds of
megabytes - StartDocked is 523 MB - and GitHub refuses any file over 100 MB
outright, so the raw form cannot be pushed at all. gzip takes that to 29 MB, a
17x reduction, because the IR is highly repetitive JSON. index.json is rewritten
to point at the .gz so a consumer still finds the file it names.

Usage:
    python publish-rewindows.py --list
    python publish-rewindows.py --only StartDocked [--dry-run]
    python publish-rewindows.py --all
"""

import argparse
import gzip
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HISTORY = os.path.join(ROOT, "history")
HEADERS = os.path.join(ROOT, "headers")
RUST = os.path.join(ROOT, "rust")
ORG = "ReWindows"
GITHUB_FILE_LIMIT = 100 * 1024 * 1024
# An empty record is a few KB; a real one is hundreds of MB.
MIN_REAL_IR = 64 * 1024


def run(args, cwd=None, check=True):
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:3])} failed: {result.stderr.strip()[:400]}")
    return result


def published_repos():
    out = run(["gh", "api", "orgs/%s/repos?per_page=100" % ORG, "--jq", ".[].name"])
    return {n.strip().lower() for n in out.stdout.splitlines() if n.strip()}


def local_targets():
    if not os.path.isdir(HISTORY):
        return []
    return sorted(d for d in os.listdir(HISTORY)
                  if os.path.isdir(os.path.join(HISTORY, d)))


def output_dirs(root):
    """Map a history target name to its emitted header directory.

    The two are named differently: history uses the binary's own name
    (Taskbar.View), headers use the corpus target id (taskbar-view). The corpus
    index carries both, so it is the thing that joins them; falling back to a
    punctuation-insensitive match covers targets pulled before the index knew
    about them.
    """
    mapping = {}
    index_path = os.path.join(ROOT, "compat-index.json")
    if os.path.exists(index_path):
        index = json.load(open(index_path, encoding="utf-8"))
        for entry in index.get("targets", []):
            stem = os.path.splitext(os.path.basename(entry.get("file", "")))[0]
            if stem and entry.get("id"):
                mapping[stem.lower()] = entry["id"]

    def normalise(name):
        return name.lower().replace(".", "").replace("-", "").replace("_", "")

    available = {}
    if os.path.isdir(root):
        for d in os.listdir(root):
            if os.path.isdir(os.path.join(root, d)):
                available[normalise(d)] = d

    def resolve(target):
        wanted = mapping.get(target.lower(), target)
        for candidate in (wanted, target):
            hit = available.get(normalise(candidate))
            if hit:
                return os.path.join(root, hit)
        return None

    return resolve


def stage(target, workdir, resolve_headers=None, resolve_rust=None):
    """Copy one target's history and headers into a repo tree.

    History is gzipped; headers are plain C++ and small enough to read in
    the browser, which is the point of having them beside the archive.
    """
    src = os.path.join(HISTORY, target)
    dst = os.path.join(workdir, "history", target)
    os.makedirs(dst, exist_ok=True)

    raw_total = 0
    gz_total = 0
    builds = []
    skipped = []

    index_path = os.path.join(src, "index.json")
    index = json.load(open(index_path, encoding="utf-8")) if os.path.exists(index_path) else {}

    for build in sorted(os.listdir(os.path.join(src, "builds"))):
        ir = os.path.join(src, "builds", build, "ir.json")
        if not os.path.isfile(ir):
            continue
        raw = os.path.getsize(ir)
        # Never archive an empty record. A PDB that resolved but contributed no
        # symbols still produces well-formed IR, and one of those has been
        # sitting in this archive as the taskbar build - 3 symbols, 0 classes -
        # long enough to look normal. Real records for these binaries run to
        # hundreds of megabytes, so the separation is four orders of magnitude
        # and needs no judgement.
        if raw < MIN_REAL_IR:
            skipped.append((build, raw))
            continue
        out_dir = os.path.join(dst, "builds", build)
        os.makedirs(out_dir, exist_ok=True)
        out = os.path.join(out_dir, "ir.json.gz")
        with open(ir, "rb") as fin, gzip.open(out, "wb", compresslevel=6) as fout:
            shutil.copyfileobj(fin, fout, length=8 * 1024 * 1024)
        gz = os.path.getsize(out)
        raw_total += raw
        gz_total += gz
        builds.append((build, raw, gz))
        if gz > GITHUB_FILE_LIMIT:
            raise RuntimeError(f"{target}/{build}: {gz/1e6:.0f} MB still over GitHub's limit")

    # Point the index at the file that actually exists now.
    for entry in index.get("builds", []):
        if isinstance(entry.get("ir"), str) and entry["ir"].endswith("ir.json"):
            entry["ir"] += ".gz"
    index["compression"] = "gzip"
    json.dump(index, open(os.path.join(dst, "index.json"), "w", encoding="utf-8"), indent=2)

    readme = [
        f"# {target}",
        "",
        f"Windissect analysis output for `{target}`, archived per build so the",
        "structure of Windows can be diffed across releases.",
        "",
        "## Builds",
        "",
        "| build | IR (raw) | IR (gzip) |",
        "| --- | ---: | ---: |",
    ]
    for build, raw, gz in builds:
        readme.append(f"| `{build}` | {raw/1e6:.1f} MB | {gz/1e6:.1f} MB |")
    readme += [
        "",
        "`ir.json` is stored gzipped: a full-depth record for a shell binary runs to",
        "hundreds of megabytes, and GitHub refuses any file over 100 MB.",
        "",
        "```sh",
        f"gunzip -c history/{target}/builds/<build>/ir.json.gz > ir.json",
        "```",
        "",
        "Diff two builds with:",
        "",
        "```sh",
        "windissect diff --old old/ir.json --new new/ir.json --markdown-out changes.md",
        "```",
        "",
        "Generated by [windissect](https://github.com/razecrs/windissect).",
    ]
    # Headers sit beside the history, matching the layout the archive already
    # uses. They are plain C++ and readable in the browser, which is what makes
    # a repo useful to someone who is not going to download a 30 MB IR.
    header_count = 0
    source = resolve_headers(target) if resolve_headers else None
    if source and os.path.isdir(source):
        shutil.copytree(source, os.path.join(workdir, "headers"), dirs_exist_ok=True)
        header_count = sum(
            len([f for f in files if f.endswith(".h")])
            for _, _, files in os.walk(os.path.join(workdir, "headers")))

    # Rust bindings, same idea: generated from the same IR, readable in place.
    rust_count = 0
    rust_source = resolve_rust(target) if resolve_rust else None
    if rust_source and os.path.isdir(rust_source):
        shutil.copytree(rust_source, os.path.join(workdir, "rust"), dirs_exist_ok=True)
        rust_count = sum(
            len([f for f in files if f.endswith(".rs")])
            for _, _, files in os.walk(os.path.join(workdir, "rust")))

    blurb = []
    if header_count:
        blurb.append(f"`headers/` carries {header_count} recovered C++ class headers.")
    if rust_count:
        blurb.append(f"`rust/` carries generated Rust bindings ({rust_count} source files).")
    if blurb:
        readme[3:3] = blurb + [""]

    open(os.path.join(workdir, "README.md"), "w", encoding="utf-8").write("\n".join(readme) + "\n")
    return raw_total, gz_total, len(builds), skipped, header_count, rust_count


def publish(target, existing, resolve_headers, resolve_rust, dry_run=False):
    repo = f"{ORG}/{target}"
    workdir = tempfile.mkdtemp(prefix="rewindows-")
    try:
        raw, gz, count, skipped, headers, rust = stage(
            target, workdir, resolve_headers, resolve_rust)
        for build, size in skipped:
            print(f"  {target:<44} SKIPPED empty record {build} ({size} bytes)")
        if not count and not headers and not rust:
            print(f"  {target:<44} nothing to publish")
            return True
        ratio = (raw / gz) if gz else 0
        print(f"  {target:<44} {count} build(s)  {raw/1e6:>8.1f} MB -> {gz/1e6:>6.1f} MB  ({ratio:.0f}x)  {headers} headers  {rust} rust")
        if dry_run:
            return True

        if target.lower() not in existing:
            run(["gh", "repo", "create", repo, "--public",
                 "--description", f"Windissect analysis output for {target}"])

        run(["git", "init", "-q", "-b", "main"], cwd=workdir)
        run(["git", "config", "user.name", "razecrs"], cwd=workdir)
        run(["git", "config", "user.email", "samuelking14th@gmail.com"], cwd=workdir)
        run(["git", "add", "-A"], cwd=workdir)
        message = (
            f"Archive {target} build record\n"
            "\n"
            "Full-depth windissect extraction, gzipped: the raw IR is well past\n"
            "GitHub's 100 MB file limit and compresses roughly 17x.\n"
            "\n"
            "Generated-by: windissect\n"
        )
        run(["git", "commit", "-q", "-m", message], cwd=workdir)
        run(["git", "remote", "add", "origin", f"https://github.com/{repo}.git"], cwd=workdir)
        run(["git", "push", "-q", "-u", "origin", "main", "--force"], cwd=workdir)
        return True
    except Exception as exc:
        print(f"  {target:<44} FAILED: {exc}")
        return False
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", action="append", default=[])
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    targets = local_targets()
    existing = published_repos()

    if args.list:
        missing = [t for t in targets if t.lower() not in existing]
        print(f"{len(targets)} local, {len(existing)} published, {len(missing)} unpublished")
        for t in missing:
            print("  ", t)
        return 0

    if args.only:
        targets = [t for t in targets if t in args.only]
        unknown = set(args.only) - set(targets)
        if unknown:
            print("unknown target(s):", ", ".join(sorted(unknown)), file=sys.stderr)
            return 2
    elif not args.all:
        print("pass --only NAME, --all, or --list", file=sys.stderr)
        return 2

    resolve_headers = output_dirs(HEADERS)
    resolve_rust = output_dirs(RUST)
    ok = sum(publish(t, existing, resolve_headers, resolve_rust, args.dry_run)
             for t in targets)
    print(f"\n{ok}/{len(targets)} published")
    return 0 if ok == len(targets) else 1


if __name__ == "__main__":
    sys.exit(main())
