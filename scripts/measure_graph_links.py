"""Measure connectivity of STIX bundles and sentence co-mention candidates."""

import argparse
import bisect
import collections
import itertools
import json
import re
import sqlite3
import sys

SCO_TYPES = {
    "artifact",
    "autonomous-system",
    "directory",
    "domain-name",
    "email-addr",
    "email-message",
    "file",
    "ipv4-addr",
    "ipv6-addr",
    "mac-addr",
    "mutex",
    "network-traffic",
    "process",
    "software",
    "url",
    "user-account",
    "windows-registry-key",
    "x509-certificate",
}

NON_NODE_TYPES = {"relationship", "report", "marking-definition", "sighting", "bundle"}
EXCLUDED_TYPES = {"identity", "artifact", "observed-data", "indicator", "note", "opinion", "location"}


def _display(obj: dict) -> str:
    """Return the display name for a node object."""
    for key in ("name", "value", "key", "account_login"):
        val = obj.get(key)
        if val not in (None, ""):
            return val if isinstance(val, str) else str(val)
    if "number" in obj:
        return str(obj["number"])
    hashes = obj.get("hashes")
    if isinstance(hashes, dict) and hashes:
        first_val = next(iter(hashes.values()))
        if isinstance(first_val, list) and first_val:
            return str(first_val[0])
        return str(first_val)
    return ""


def _load_jobs(conn: sqlite3.Connection, job_filter: str | None) -> tuple[list[dict], list[str]]:
    """Load jobs from the database, parsing bundle JSON."""
    cursor = conn.execute(
        "SELECT id, original_filename, status, report_text, bundle_json FROM jobs "
        "WHERE bundle_json IS NOT NULL AND bundle_json != '' ORDER BY created_at"
    )
    jobs: list[dict] = []
    skipped: list[str] = []
    for row in cursor.fetchall():
        job_id, filename, status, report_text, bundle_json = row
        if job_filter and not job_id.startswith(job_filter):
            continue
        try:
            parsed = json.loads(bundle_json)
        except (json.JSONDecodeError, TypeError):
            skipped.append(job_id)
            continue
        objects: list[dict] = []
        if isinstance(parsed, dict):
            raw_objects = parsed.get("objects")
            if isinstance(raw_objects, list):
                objects = [obj for obj in raw_objects if isinstance(obj, dict)]
        jobs.append(
            {
                "id": job_id,
                "filename": filename or "",
                "status": status or "",
                "text": report_text or "",
                "objects": objects,
            }
        )
    return jobs, skipped


def _extracted_count(conn: sqlite3.Connection, job_id: str) -> int:
    """Count extracted relationships for a job."""
    cursor = conn.execute("SELECT count(*) FROM relationships WHERE job_id = ?", (job_id,))
    row = cursor.fetchone()
    return row[0] if row else 0


def _components(node_ids: set[str], rels: list[dict]) -> list[set[str]]:
    """Compute connected components using union-find."""
    parent: dict[str, str] = {nid: nid for nid in node_ids}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for rel in rels:
        src = rel.get("source_ref")
        tgt = rel.get("target_ref")
        if isinstance(src, str) and isinstance(tgt, str) and src in node_ids and tgt in node_ids:
            union(src, tgt)

    groups: dict[str, set[str]] = {}
    for nid in node_ids:
        root = find(nid)
        groups.setdefault(root, set()).add(nid)
    return list(groups.values())


def _split_sentences(text: str) -> list[tuple[int, str]]:
    """Split text into sentences with absolute start offsets."""
    if not text:
        return []
    pattern = re.compile(r"(?<=[.!?])\s+|\n{2,}")
    matches = list(pattern.finditer(text))
    sentences: list[tuple[int, str]] = []
    prev_end = 0
    for m in matches:
        s = text[prev_end:m.start()]
        stripped = s.strip()
        if stripped:
            start_offset = text.index(stripped, prev_end)
            sentences.append((start_offset, stripped))
        prev_end = m.end()
    tail = text[prev_end:]
    stripped_tail = tail.strip()
    if stripped_tail:
        start_offset = text.index(stripped_tail, prev_end)
        sentences.append((start_offset, stripped_tail))
    return sentences


def _build_sentence_index(nodes: list[dict], text: str) -> dict[str, set[int]]:
    """Map node ids to sentence indexes where their display name appears."""
    sentences = _split_sentences(text)
    if not sentences:
        return {}
    starts = [s[0] for s in sentences]
    index: dict[str, set[int]] = {}
    for node in nodes:
        name = _display(node)
        if len(name) < 4:
            continue
        pattern_str = re.escape(name)
        if name[0].isalnum():
            pattern_str = r"\b" + pattern_str
        if name[-1].isalnum():
            pattern_str = pattern_str + r"\b"
        try:
            regex = re.compile(pattern_str, re.IGNORECASE)
        except re.error:
            continue
        found: set[int] = set()
        for m in regex.finditer(text):
            offset = m.start()
            idx = bisect.bisect_right(starts, offset) - 1
            if idx >= 0:
                found.add(idx)
        if found:
            index[node["id"]] = found
    return index


def _comention_candidates(
    nodes: list[dict], rels: list[dict], text: str
) -> tuple[collections.Counter, set[str]]:
    """Find co-mentioned node pairs without existing edges."""
    if not text:
        return collections.Counter(), set()

    node_by_id = {n["id"]: n for n in nodes if "id" in n}
    linked: set[frozenset[str]] = set()
    degree: dict[str, int] = {nid: 0 for nid in node_by_id}
    for rel in rels:
        src = rel.get("source_ref")
        tgt = rel.get("target_ref")
        if isinstance(src, str) and isinstance(tgt, str):
            linked.add(frozenset((src, tgt)))
            if src in degree:
                degree[src] += 1
            if tgt in degree:
                degree[tgt] += 1

    sentence_index = _build_sentence_index(nodes, text)
    sentence_to_nodes: dict[int, list[str]] = collections.defaultdict(list)
    for nid, sidxs in sentence_index.items():
        for sidx in sidxs:
            sentence_to_nodes[sidx].append(nid)

    counter: collections.Counter = collections.Counter()
    seen_pairs: set[frozenset[str]] = set()
    rescuable: set[str] = set()

    for sidx, nids in sentence_to_nodes.items():
        if len(nids) < 2:
            continue
        for a_id, b_id in itertools.combinations(nids, 2):
            if a_id == b_id:
                continue
            pair = frozenset((a_id, b_id))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            if pair in linked:
                continue
            node_a = node_by_id.get(a_id)
            node_b = node_by_id.get(b_id)
            if not node_a or not node_b:
                continue
            type_a = node_a.get("type", "")
            type_b = node_b.get("type", "")
            if type_a in SCO_TYPES and type_b in SCO_TYPES:
                continue
            if type_a == "attack-pattern" and type_b == "attack-pattern":
                continue
            if type_a in EXCLUDED_TYPES or type_b in EXCLUDED_TYPES:
                continue
            key = tuple(sorted((type_a, type_b)))
            counter[key] += 1
            if degree.get(a_id, 0) == 0:
                rescuable.add(a_id)
            if degree.get(b_id, 0) == 0:
                rescuable.add(b_id)

    return counter, rescuable


def _bundle_stats(job: dict, extracted: int) -> dict:
    """Compute statistics for a single job bundle."""
    objects = job.get("objects", [])
    nodes: list[dict] = []
    rels: list[dict] = []
    report_obj: dict | None = None

    for obj in objects:
        otype = obj.get("type")
        if otype == "relationship":
            rels.append(obj)
        elif otype == "report":
            report_obj = obj
        elif otype not in NON_NODE_TYPES:
            if otype == "identity" and "CTIParsor" in obj.get("name", ""):
                continue
            nodes.append(obj)

    node_ids = {n["id"] for n in nodes if "id" in n}
    nodes_by_type: collections.Counter = collections.Counter(n.get("type", "") for n in nodes)
    edges = len(rels)
    verbs: collections.Counter = collections.Counter(r.get("relationship_type", "") for r in rels)
    labels: collections.Counter = collections.Counter()
    rules: collections.Counter = collections.Counter()

    for r in rels:
        label = r.get("x_evidence_label")
        labels[label if label is not None else "(absent)"] += 1
        inference = r.get("x_inference_rule")
        policy = r.get("x_policy_rule")
        if inference:
            tag = inference.split(":")[0]
        elif policy:
            tag = "policy-pin"
        else:
            tag = "(none)"
        rules[tag] += 1

    degree: dict[str, int] = {nid: 0 for nid in node_ids}
    for r in rels:
        src = r.get("source_ref")
        tgt = r.get("target_ref")
        if isinstance(src, str) and src in degree:
            degree[src] += 1
        if isinstance(tgt, str) and tgt in degree:
            degree[tgt] += 1

    isolated = sum(1 for nid in node_ids if degree.get(nid, 0) == 0)
    isolated_by_type: collections.Counter = collections.Counter()
    for n in nodes:
        nid = n.get("id")
        if nid in node_ids and degree.get(nid, 0) == 0:
            isolated_by_type[n.get("type", "")] += 1

    comps = _components(node_ids, rels)
    num_components = len(comps)
    largest = max((len(c) for c in comps), default=0)

    synthesis = None
    if report_obj and "x_synthesis_stats" in report_obj:
        synthesis = report_obj["x_synthesis_stats"]

    text = job.get("text", "")
    candidates, rescuable = _comention_candidates(nodes, rels, text)
    candidate_total = sum(candidates.values())

    return {
        "nodes": len(nodes),
        "nodes_by_type": nodes_by_type,
        "edges": edges,
        "verbs": verbs,
        "labels": labels,
        "rules": rules,
        "degree": degree,
        "isolated": isolated,
        "isolated_by_type": isolated_by_type,
        "components": num_components,
        "largest": largest,
        "synthesis": synthesis,
        "extracted": extracted,
        "candidates": candidates,
        "candidate_total": candidate_total,
        "rescuable_isolated": len(rescuable),
    }


def _pct(part: int, whole: int) -> str:
    """Return percentage as a string, or '-' if whole is zero."""
    if whole == 0:
        return "-"
    return f"{part / whole * 100:.1f}"


def _print_table(headers: list[str], rows: list[list[object]]) -> None:
    """Print a plain-text table with aligned columns."""
    if not rows:
        print("\t".join(headers))
        print("-" * (sum(len(h) for h in headers) + 3 * (len(headers) - 1)))
        print()
        return

    str_rows = [[str(cell) if cell is not None else "" for cell in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in str_rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(cell))

    def fmt_row(cells: list[str]) -> str:
        parts = []
        for i, cell in enumerate(cells):
            if i >= len(headers):
                break
            if i < len(widths):
                w = widths[i]
                # Right-align anything that parses as a number.
                try:
                    float(cell)
                    parts.append(cell.rjust(w))
                except (ValueError, TypeError):
                    parts.append(cell.ljust(w))
            else:
                parts.append(cell)
        return "  ".join(parts)

    print(fmt_row(headers))
    print("-" * (sum(widths) + 2 * (len(widths) - 1)))
    for row in str_rows:
        print(fmt_row(row))
    print()


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Measure STIX bundle connectivity")
    parser.add_argument("--db", default="cti_stix.db")
    parser.add_argument("--job", default=None)
    parser.add_argument("--json", default=None)
    args = parser.parse_args(argv)

    conn = sqlite3.connect(args.db)
    jobs, skipped = _load_jobs(conn, args.job)

    stats_list: list[dict] = []
    for job in jobs:
        extracted = _extracted_count(conn, job["id"])
        stats = _bundle_stats(job, extracted)
        stats["job_id"] = job["id"]
        stats["filename"] = job["filename"]
        stats_list.append(stats)

    # 1. Per-job table
    headers = [
        "job", "file", "nodes", "edges", "extracted", "isolated", "iso%", "comps",
        "largest%", "reported", "assessed", "observed", "inferred", "absent", "cand", "rescue",
    ]
    rows: list[list[object]] = []
    total_nodes = 0
    total_edges = 0
    total_extracted = 0
    total_isolated = 0
    total_comps = 0
    total_reported = 0
    total_assessed = 0
    total_observed = 0
    total_inferred = 0
    total_absent = 0
    total_cand = 0
    total_rescue = 0

    for stats in stats_list:
        job8 = stats["job_id"][:8]
        file32 = stats["filename"][:32]
        nodes = stats["nodes"]
        edges = stats["edges"]
        extracted = stats["extracted"]
        isolated = stats["isolated"]
        iso_pct = _pct(isolated, nodes)
        comps = stats["components"]
        largest_pct = _pct(stats["largest"], nodes)
        labels = stats["labels"]
        reported = labels.get("reported", 0)
        assessed = labels.get("assessed", 0)
        observed = labels.get("observed", 0)
        inferred = labels.get("inferred", 0)
        absent = labels.get("(absent)", 0)
        cand = stats["candidate_total"]
        rescue = stats["rescuable_isolated"]

        rows.append([
            job8, file32, nodes, edges, extracted, isolated, iso_pct, comps, largest_pct,
            reported, assessed, observed, inferred, absent, cand, rescue,
        ])

        total_nodes += nodes
        total_edges += edges
        total_extracted += extracted
        total_isolated += isolated
        total_comps += comps
        total_reported += reported
        total_assessed += assessed
        total_observed += observed
        total_inferred += inferred
        total_absent += absent
        total_cand += cand
        total_rescue += rescue

    total_iso_pct = _pct(total_isolated, total_nodes)
    rows.append([
        "TOTAL", "", total_nodes, total_edges, total_extracted, total_isolated, total_iso_pct,
        total_comps, "-", total_reported, total_assessed, total_observed, total_inferred,
        total_absent, total_cand, total_rescue,
    ])
    _print_table(headers, rows)

    # 2. Top verbs
    verb_counter: collections.Counter = collections.Counter()
    for stats in stats_list:
        verb_counter.update(stats["verbs"])
    verb_rows = []
    for verb, count in verb_counter.most_common(15):
        share = _pct(count, total_edges)
        verb_rows.append([verb, count, share])
    _print_table(["verb", "count", "share%"], verb_rows)

    # 3. Edge sources
    rule_counter: collections.Counter = collections.Counter()
    for stats in stats_list:
        rule_counter.update(stats["rules"])
    rule_rows = [[tag, count] for tag, count in rule_counter.most_common()]
    _print_table(["source tag", "count"], rule_rows)

    # 4. Isolated nodes by type
    iso_type_counter: collections.Counter = collections.Counter()
    node_type_counter: collections.Counter = collections.Counter()
    for stats in stats_list:
        iso_type_counter.update(stats["isolated_by_type"])
        node_type_counter.update(stats["nodes_by_type"])
    iso_rows = []
    for t, iso_count in iso_type_counter.most_common():
        node_count = node_type_counter.get(t, 0)
        pct = _pct(iso_count, node_count)
        iso_rows.append([t, node_count, iso_count, pct])
    _print_table(["type", "nodes", "isolated", "iso%"], iso_rows)

    # 5. Co-mention candidates
    cand_counter: collections.Counter = collections.Counter()
    for stats in stats_list:
        cand_counter.update(stats["candidates"])
    cand_rows = []
    for (type_a, type_b), count in cand_counter.most_common(20):
        cand_rows.append([type_a, type_b, count])
    _print_table(["type_a", "type_b", "pairs"], cand_rows)
    print(f"candidate pairs total: {total_cand}  rescuable isolated nodes: {total_rescue}")
    print()

    # 6. Synthesis stats
    for stats in stats_list:
        synthesis = stats.get("synthesis")
        if not synthesis:
            continue
        job8 = stats["job_id"][:8]
        pin = synthesis.get("pin", {})
        budget = pin.get("budget", "n/a")
        rules_list = pin.get("rules", [])
        emitted = sum(r.get("emitted", 0) for r in rules_list if isinstance(r, dict))
        truncated = sum(r.get("truncated", 0) for r in rules_list if isinstance(r, dict))
        completion = synthesis.get("completion", {})
        reference = completion.get("reference_added", "n/a")
        transitive = completion.get("transitive_added", "n/a")
        long_distance = completion.get("long_distance_added", "n/a")
        capped = completion.get("capped", "n/a")
        print(
            f"{job8} pin: budget={budget} emitted={emitted} truncated={truncated} | "
            f"completion: reference={reference} transitive={transitive} "
            f"long_distance={long_distance} capped={capped}"
        )

    # 7. Skipped jobs
    if skipped:
        print(f"skipped (unparsable bundle): {', '.join(skipped)}")

    # JSON output
    if args.json:
        json_data = []
        for stats in stats_list:
            d = dict(stats)
            d.pop("degree", None)
            for key in list(d.keys()):
                val = d[key]
                if isinstance(val, collections.Counter):
                    new_dict = {}
                    for k, v in val.items():
                        if isinstance(k, tuple):
                            k = ">".join(str(x) for x in k)
                        new_dict[str(k)] = v
                    d[key] = new_dict
            json_data.append(d)
        with open(args.json, "w") as f:
            json.dump(json_data, f, indent=2)

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
