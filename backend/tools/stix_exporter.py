from pathlib import Path
from datetime import datetime, timezone
import uuid

from agno.tools import tool
from stix2 import (
    Bundle,
    Indicator,
    Malware,
    AttackPattern,
    ThreatActor,
    Campaign,
    Relationship,
)

from src.config import get_stix_output_dir
from src.models.extractor import StixBundleInput


REPORT_CENTRIC_PREFIXES = (
    "the report describes",
    "the report mentions",
    "named in the report",
    "identified in the report",
    "focus of the report",
    "mentioned as",
    "named as",
)

GENERIC_BAD_DESCRIPTIONS = {
    "malware description",
    "cybercrime strategy",
    "threat actor description",
    "description of x in the report",
    "significant threat",
    "prevalent threat",
}

ALLOWED_DOMAIN_EXPORT_ROLES = {
    "malicious_infrastructure",
    "phishing_infrastructure",
    "payload_delivery",
    "c2",
    "exfiltration",
}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _key(obj_type: str, name: str) -> tuple[str, str]:
    return (obj_type.strip().lower(), name.strip().lower())


def clean_description(text: str | None) -> str | None:
    if not text:
        return None

    cleaned = " ".join(text.strip().split())
    lowered = cleaned.lower()

    if lowered in GENERIC_BAD_DESCRIPTIONS:
        return None

    for prefix in REPORT_CENTRIC_PREFIXES:
        if lowered.startswith(prefix):
            return None

    return cleaned


def _relationship_fallback_description(rel) -> str:
    source = rel.source_name.strip()
    target = rel.target_name.strip()
    rel_type = rel.relationship_type.strip()

    if rel_type == "uses":
        return f"{source} uses {target}."
    if rel_type == "delivers":
        return f"{source} delivers {target}."
    if rel_type == "targets":
        return f"{source} targets {target}."
    if rel_type == "attributed-to":
        return f"{source} is attributed to {target}."
    if rel_type == "indicates":
        return f"{source} indicates {target}."
    return f"{source} is related to {target}."


def _should_export_domain(domain) -> bool:
    decision = getattr(domain, "decision", None)
    role = getattr(domain, "role", None)

    if decision != "export_indicator":
        return False

    if role not in ALLOWED_DOMAIN_EXPORT_ROLES:
        return False

    return True


def export_verified_bundle_to_stix(
    verified_bundle: StixBundleInput,
    output_filename: str = "stix_bundle_final.json",
    output_dir: str | Path | None = None,
) -> str:
    objects = []
    entity_refs: dict[tuple[str, str], str] = {}

    resolved_output_dir = Path(output_dir).resolve() if output_dir else get_stix_output_dir()
    resolved_output_dir.mkdir(parents=True, exist_ok=True)

    def remember(obj_type: str, name: str, obj_id: str) -> None:
        entity_refs[_key(obj_type, name)] = obj_id

    for h in verified_bundle.file_hashes:
        now = _now()
        obj_id = f"indicator--{uuid.uuid4()}"

        description = clean_description(h.context or h.evidence)

        kwargs = dict(
            id=obj_id,
            created=now,
            modified=now,
            name=f"{h.algorithm} Hash",
            pattern=f"[file:hashes.'{h.algorithm}' = '{h.value}']",
            pattern_type="stix",
            valid_from=now,
            labels=["malicious-activity"],
        )
        if description:
            kwargs["description"] = description

        obj = Indicator(**kwargs)
        objects.append(obj)
        remember("indicator", h.value, obj_id)

    for ip in verified_bundle.ipv4s:
        now = _now()
        obj_id = f"indicator--{uuid.uuid4()}"

        description = clean_description(ip.context or ip.evidence)

        kwargs = dict(
            id=obj_id,
            created=now,
            modified=now,
            name="IPv4 Address",
            pattern=f"[ipv4-addr:value = '{ip.value}']",
            pattern_type="stix",
            valid_from=now,
        )
        if description:
            kwargs["description"] = description

        obj = Indicator(**kwargs)
        objects.append(obj)
        remember("indicator", ip.value, obj_id)

    for domain in verified_bundle.domains:
        if not _should_export_domain(domain):
            continue

        now = _now()
        obj_id = f"indicator--{uuid.uuid4()}"

        description = clean_description(domain.context or domain.evidence)

        kwargs = dict(
            id=obj_id,
            created=now,
            modified=now,
            name="Domain Name",
            pattern=f"[domain-name:value = '{domain.value}']",
            pattern_type="stix",
            valid_from=now,
        )
        if description:
            kwargs["description"] = description

        obj = Indicator(**kwargs)
        objects.append(obj)
        remember("indicator", domain.value, obj_id)

    for m in verified_bundle.malwares:
        now = _now()
        obj_id = f"malware--{uuid.uuid4()}"

        description = clean_description(m.context or m.evidence)

        kwargs = dict(
            id=obj_id,
            created=now,
            modified=now,
            name=m.name,
            is_family=True,
        )
        if description:
            kwargs["description"] = description

        obj = Malware(**kwargs)
        objects.append(obj)
        remember("malware", m.name, obj_id)

    for ap in verified_bundle.attack_patterns:
        now = _now()
        obj_id = f"attack-pattern--{uuid.uuid4()}"

        description = clean_description(ap.context or ap.evidence)

        kwargs = dict(
            id=obj_id,
            created=now,
            modified=now,
            name=ap.name,
        )
        if description:
            kwargs["description"] = description

        obj = AttackPattern(**kwargs)
        objects.append(obj)
        remember("attack-pattern", ap.name, obj_id)

    for ta in getattr(verified_bundle, "threat_actors", []):
        now = _now()
        obj_id = f"threat-actor--{uuid.uuid4()}"

        description = clean_description(ta.context or ta.evidence)

        kwargs = dict(
            id=obj_id,
            created=now,
            modified=now,
            name=ta.name,
        )
        if description:
            kwargs["description"] = description

        obj = ThreatActor(**kwargs)
        objects.append(obj)
        remember("threat-actor", ta.name, obj_id)

    for c in getattr(verified_bundle, "campaigns", []):
        now = _now()
        obj_id = f"campaign--{uuid.uuid4()}"

        description = clean_description(c.context or c.evidence)

        kwargs = dict(
            id=obj_id,
            created=now,
            modified=now,
            name=c.name,
        )
        if description:
            kwargs["description"] = description

        obj = Campaign(**kwargs)
        objects.append(obj)
        remember("campaign", c.name, obj_id)

    seen_relationships: set[tuple[str, str, str]] = set()

    for rel in getattr(verified_bundle, "relationships", []):
        source_ref = entity_refs.get(_key(rel.source_type, rel.source_name))
        target_ref = entity_refs.get(_key(rel.target_type, rel.target_name))

        if not source_ref or not target_ref:
            print(
                "Skipping relationship because endpoint was not found: "
                f"{rel.source_type}:{rel.source_name} -> "
                f"{rel.target_type}:{rel.target_name}"
            )
            continue

        rel_key = (source_ref, rel.relationship_type, target_ref)
        if rel_key in seen_relationships:
            continue
        seen_relationships.add(rel_key)

        now = _now()
        description = clean_description(rel.context or rel.evidence)
        if not description:
            description = _relationship_fallback_description(rel)

        obj = Relationship(
            id=f"relationship--{uuid.uuid4()}",
            created=now,
            modified=now,
            relationship_type=rel.relationship_type,
            source_ref=source_ref,
            target_ref=target_ref,
            description=description,
        )

        objects.append(obj)

    bundle = Bundle(objects=objects)
    serialized = bundle.serialize(pretty=True)

    file_path = resolved_output_dir / output_filename
    file_path.write_text(serialized, encoding="utf-8")

    print(f"Final STIX 2.1 Bundle exported with {len(objects)} objects")
    print(f"   Saved to: {file_path}")

    return str(file_path)

@tool
def export_verified_bundle_to_stix_tool(
    verified_bundle: StixBundleInput,
    output_filename: str = "stix_bundle_final.json",
    output_dir: str | None = None,
) -> str:
    return export_verified_bundle_to_stix(
        verified_bundle=verified_bundle,
        output_filename=output_filename,
        output_dir=output_dir,
    )

__all__ = ["export_verified_bundle_to_stix", "export_verified_bundle_to_stix_tool"]