from pathlib import Path
from datetime import datetime
import uuid

from agno.tools import tool
from stix2 import Bundle, Indicator, Malware, AttackPattern, ThreatActor, Campaign, Relationship

from project_s.config import get_stix_output_dir
from project_s.models.extractor import StixBundleInput


@tool
def create_stix_bundle(
    input_data: StixBundleInput,
    output_filename: str = "stix_output.json",
    output_dir: str | None = None,
):
    objects = []
    resolved_output_dir = Path(output_dir).resolve() if output_dir else get_stix_output_dir()
    resolved_output_dir.mkdir(parents=True, exist_ok=True)

    for hash in input_data.file_hashes:
        pattern = f"[file:hashes.'{hash.algorithm}' = '{hash.value}']"
        data = {
            "type": "indicator",
            "id": f"indicator--{uuid.uuid4()}",
            "created": datetime.now().isoformat() + "Z",
            "name": f"{hash.algorithm} Hash",
            "description": hash.context or hash.evidence,
            "pattern": pattern,
            "pattern_type": "stix",
            "labels": ["malicious-activity"] if "malicious" in (hash.context or "").lower() else [],
        }

        try:
            objects.append(Indicator(**data))
        except Exception as e:
            print(f"Hash indicator failed: {e}")

    for ip in input_data.ipv4s:
        data = {
            "type": "indicator",
            "id": f"indicator--{uuid.uuid4()}",
            "created": datetime.now().isoformat() + "Z",
            "name": "IPv4 Address",
            "description": ip.context or ip.evidence,
            "pattern": f"[ipv4-addr:value = '{ip.value}']",
            "pattern_type": "stix",
        }

        try:
            objects.append(Indicator(**data))
        except Exception as e:
            print(f"IP indicator failed: {e}")

    for domain in input_data.domains:
        data = {
            "type": "indicator",
            "id": f"indicator--{uuid.uuid4()}",
            "created": datetime.now().isoformat() + "Z",
            "name": "Domain Name",
            "description": domain.context or domain.evidence,
            "pattern": f"[domain-name:value = '{domain.value}']",
            "pattern_type": "stix",
        }

        try:
            objects.append(Indicator(**data))
        except Exception as e:
            print(f"Domain indicator failed: {e}")

    for malware in input_data.malwares:
        data = {
            "type": "malware",
            "id": f"malware--{uuid.uuid4()}",
            "created": datetime.now().isoformat() + "Z",
            "name": malware.name,
            "description": malware.context or malware.evidence,
            "malware_types": ["malware"],
        }

        try:
            objects.append(Malware(**data))
        except Exception as e:
            print(f"Malware failed: {e}")

    for ap in input_data.attack_patterns:
        data = {
            "type": "attack-pattern",
            "id": f"attack-pattern--{uuid.uuid4()}",
            "created": datetime.now().isoformat() + "Z",
            "name": ap.name,
            "description": ap.context or ap.evidence,
        }

        try:
            objects.append(AttackPattern(**data))
        except Exception as e:
            print(f"Attack Pattern failed: {e}")

    for threat_actor in input_data.threat_actors:
        data = {
            "type": "threat-actor",
            "id": f"threat-actor--{uuid.uuid4()}",
            "created": datetime.now().isoformat() + "Z",
            "name": threat_actor.name,
            "description": threat_actor.context or threat_actor.evidence,
        }

        try:
            objects.append(ThreatActor(**data))
        except Exception as e:
            print(f"Threat Actor failed: {e}")

    for campaign in input_data.campaigns:
        data = {
            "type": "campaign",
            "id": f"campaign--{uuid.uuid4()}",
            "created": datetime.now().isoformat() + "Z",
            "name": campaign.name,
            "description": campaign.context or campaign.evidence,
        }

        try:
            objects.append(Campaign(**data))
        except Exception as e:
            print(f"Campaign failed: {e}")

    bundle = Bundle(objects=objects)
    serialized = bundle.serialize(pretty=True)

    file_path = resolved_output_dir / output_filename

    try:
        file_path.write_text(serialized, encoding="utf-8")
        print(f"Successfully saved STIX bundle with {len(objects)} objects to {file_path}")
    except Exception as e:
        print(f"Failed to save file: {e}")

    return {
        "status": "success",
        "object_count": len(objects),
        "saved_to": str(file_path),
    }