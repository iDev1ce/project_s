from pathlib import Path

from src.agents.stix_agent import extractor_agent
from src.agents.verifier_agent import verifier_agent
from src.models.extractor import StixBundleInput
from src.tools.relationship_builder import build_relationships_after_verification
from src.tools.stix_exporter import export_verified_bundle_to_stix


def process_report(input_path: str, output_name: str = "stix_bundle_final.json") -> str:
    input_path = str(Path(input_path).resolve())

    extractor_result = extractor_agent.run(
        input=f"Extract a draft StixBundleInput from this document: {input_path}"
    )

    draft_bundle = extractor_result.content
    if not isinstance(draft_bundle, StixBundleInput):
        raise TypeError(f"Extractor returned {type(draft_bundle)}, expected StixBundleInput")

    verifier_prompt = f"""
Original document path: {input_path}

Draft bundle:
{draft_bundle.model_dump_json(indent = 2)}

Review this and return an improved StixBundleInput.
Use load_document_tool if you need to double-check the source document.
Include `relationships` as an empty list. Relationship building happens in a later deterministic step.
"""

    verifier_result = verifier_agent.run(verifier_prompt)

    verified_bundle = verifier_result.content
    if not isinstance(verified_bundle, StixBundleInput):
        raise TypeError(f"Verifier returned {type(verified_bundle)}, expected StixBundleInput")

    verified_bundle = build_relationships_after_verification(verified_bundle)

    output_path = export_verified_bundle_to_stix(
        verified_bundle=verified_bundle,
        output_filename=output_name,
    )

    return output_path