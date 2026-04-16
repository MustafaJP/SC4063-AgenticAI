import re
from collections import Counter, defaultdict

from agent.models import Evidence
from agent.utils import shannon_entropy


QUERY_RE = re.compile(r"query=([A-Za-z0-9._-]+)", re.IGNORECASE)
QTYPE_RE = re.compile(r"type=([A-Za-z0-9._-]+)", re.IGNORECASE)


def _extract_query_and_qtype(item):
    """
    Try to recover the actual DNS query and qtype from:
    1. raw_json
    2. summary text
    3. fallback text

    This avoids treating the whole summary string as the domain.
    """
    raw = item.get("raw_json") or item.get("raw") or {}
    summary = str(item.get("summary") or "")

    raw_query = raw.get("query") or raw.get("dns_query") or raw.get("host") or raw.get("domain")
    raw_qtype = raw.get("qtype") or raw.get("query_type")

    if raw_query:
        query = str(raw_query).strip().lower()
    else:
        match = QUERY_RE.search(summary)
        query = match.group(1).strip().lower() if match else summary.strip().lower()

    if raw_qtype:
        qtype = str(raw_qtype).strip().upper()
    else:
        match = QTYPE_RE.search(summary)
        qtype = match.group(1).strip().upper() if match else "A"

    return query, qtype


def _base_domain(query):
    parts = [p for p in query.split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return query


def analyze_dns(dns_events, config):
    """
    Detect suspicious DNS activity.

    Important:
    - This file should support a conservative classification strategy.
    - High entropy alone should indicate suspicious DNS, not automatically tunneling.
    - Additional recurrence and spread signals improve confidence.
    """
    evidence_items = []

    parsed = []
    for item in dns_events:
        query, qtype = _extract_query_and_qtype(item)
        src_ip = item.get("src_ip", "unknown")
        parsed.append({
            "item": item,
            "query": query,
            "qtype": qtype,
            "src_ip": src_ip,
            "base_domain": _base_domain(query),
        })

    query_counts = Counter(x["query"] for x in parsed if x["query"])
    base_domain_counts = Counter(x["base_domain"] for x in parsed if x["base_domain"])

    domain_to_hosts = defaultdict(set)
    for x in parsed:
        if x["query"]:
            domain_to_hosts[x["query"]].add(x["src_ip"])
        if x["base_domain"]:
            domain_to_hosts[x["base_domain"]].add(x["src_ip"])

    base_to_subdomains = defaultdict(set)
    for x in parsed:
        query = x["query"]
        base_domain = x["base_domain"]
        if not query or not base_domain:
            continue
        if query != base_domain:
            base_to_subdomains[base_domain].add(query)

    for x in parsed:
        item = x["item"]
        query = x["query"]
        qtype = x["qtype"]
        src_ip = x["src_ip"]
        base_domain = x["base_domain"]

        if not query:
            continue

        # Skip allowlisted domains (Microsoft, Azure, Google, etc.)
        if base_domain in config.allowlisted_domains:
            continue
        # Also check if any allowlisted domain is a suffix of the query
        if any(query.endswith("." + d) or query == d for d in config.allowlisted_domains):
            continue

        entropy = shannon_entropy(query.replace(".", ""))
        label_lengths = [len(part) for part in query.split(".") if part]

        score = 0.0
        reasons = []

        # Base entropy signal
        if entropy >= config.entropy_threshold:
            score += 0.5
            reasons.append("high_entropy")

        # Long subdomain labels are suspicious
        if any(length > 25 for length in label_lengths):
            score += 0.2
            reasons.append("long_label")

        # TXT is often more suspicious than standard A lookups
        if qtype == "TXT":
            score += 0.2
            reasons.append("txt_query")

        # Same domain queried repeatedly across the bundle
        if query_counts.get(query, 0) >= 3:
            score += 0.2
            reasons.append("repeated_domain")

        # Same domain or base domain queried from multiple hosts
        if len(domain_to_hosts.get(query, set())) >= 2 or len(domain_to_hosts.get(base_domain, set())) >= 2:
            score += 0.2
            reasons.append("multi_host_domain")

        # Many varying subdomains under the same base domain can suggest tunneling/C2 patterns
        if len(base_to_subdomains.get(base_domain, set())) >= 3:
            score += 0.2
            reasons.append("varying_subdomains_same_base")

        if score < 0.5:
            continue

        entity = f"{src_ip}:{query}"

        evidence_items.append(
            Evidence(
                source="dns_analysis",
                indicator="high_entropy_dns",
                value=query,
                score=round(min(score, 1.0), 3),
                details={
                    "entity": entity,
                    "src_ip": src_ip,
                    "query": query,
                    "base_domain": base_domain,
                    "qtype": qtype,
                    "entropy": round(entropy, 3),
                    "query_count": query_counts.get(query, 0),
                    "base_domain_count": base_domain_counts.get(base_domain, 0),
                    "host_count_for_query": len(domain_to_hosts.get(query, set())),
                    "host_count_for_base_domain": len(domain_to_hosts.get(base_domain, set())),
                    "varying_subdomain_count": len(base_to_subdomains.get(base_domain, set())),
                    "reasons": reasons,
                    "event_timestamp": item.get("event_timestamp"),
                },
            )
        )

    return evidence_items