from __future__ import annotations

import re
from typing import Iterable

from backend.models.extractor import StixBundleInput, ExtractedRelationship


DELIVERY_VERBS = (
    "spread",
    "spreads",
    "spreading",
    "distributed",
    "distribute",
    "distributes",
    "delivers",
    "deliver",
    "delivered",
    "download",
    "downloads",
    "downloaded",
    "execute",
    "executes",
    "executed",
    "drop",
    "drops",
    "dropped",
    "load",
    "loads",
    "loaded",
    "deploy",
    "deploys",
    "deployed",
    "circulate",
    "circulates",
    "circulated",
)

USE_VERBS = (
    "uses",
    "used",
    "using",
    "leverages",
    "leveraged",
    "employs",
    "employed",
    "utilizes",
    "utilized",
    "abuses",
    "abused",
)

ATTRIBUTION_CUES = (
    "attributed to",
    "linked to",
    "associated with",
    "tracked as",
    "known as",
)

EXPLICIT_RELATED_CUES = (
    "related to",
    "associated with",
    "linked to",
    "connected to",
)

REPORT_CENTRIC_PHRASES = (
    "the report describes",
    "the report mentions",
    "named in the report",
    "identified in the report",
    "focus of the report",
    "mentioned as",
    "named as",
)

GENERIC_RELATIONSHIP_BAD_TEXT = {
    "named as the malware focus of the report.",
    "named as additional malware downloaded and executed.",
    "named as malware being spread and downloaded.",
}

SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")
WHITESPACE_RE = re.compile(r"\s+")
MAX_EVIDENCE_LEN = 500


def _norm(value: str | None) -> str:
    if not value:
        return ""
    return " ".join(value.strip().lower().split())


def _text(*parts: str | None) -> str:
    return " ".join(part for part in parts if part).strip()


def _entity_list(bundle: StixBundleInput, *field_names: str) -> list:
    for field_name in field_names:
        value = getattr(bundle, field_name, None)
        if value is not None:
            return list(value or [])
    return []


def _contains_name(text: str, name: str) -> bool:
    norm_text = _norm(text)
    norm_name = _norm(name)
    if not norm_text or not norm_name:
        return False
    return norm_name in norm_text


def _has_any(text: str, phrases: Iterable[str]) -> bool:
    norm_text = _norm(text)
    return any(phrase in norm_text for phrase in phrases)


def _is_report_centric(text: str) -> bool:
    norm_text = _norm(text)
    if not norm_text:
        return False
    if norm_text in GENERIC_RELATIONSHIP_BAD_TEXT:
        return True
    return any(phrase in norm_text for phrase in REPORT_CENTRIC_PHRASES)


def _clean_rel_text(text: str | None) -> str | None:
    if not text:
        return None

    cleaned = WHITESPACE_RE.sub(" ", text.strip())
    if not cleaned:
        return None

    if _is_report_centric(cleaned):
        return None

    if len(cleaned) > MAX_EVIDENCE_LEN:
        cleaned = cleaned[:MAX_EVIDENCE_LEN].rstrip() + "..."

    return cleaned


def _entity_text(item) -> str:
    return _text(
        getattr(item, "evidence", None),
        getattr(item, "context", None),
    )


def _split_document_chunks(document_text: str | None) -> list[str]:
    if not document_text:
        return []

    raw = document_text.replace("\r\n", "\n")
    chunks: list[str] = []

    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", raw) if p.strip()]
    for paragraph in paragraphs:
        chunks.append(paragraph)
        for sentence in SENTENCE_SPLIT_RE.split(paragraph):
            sentence = sentence.strip()
            if sentence:
                chunks.append(sentence)

    seen = set()
    deduped: list[str] = []
    for chunk in chunks:
        key = _norm(chunk)
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(chunk)

    return deduped


def _supporting_chunks(document_text: str | None, *entity_items) -> list[str]:
    chunks = _split_document_chunks(document_text)

    for item in entity_items:
        text = _entity_text(item)
        if text:
            chunks.append(text)

    seen = set()
    out: list[str] = []
    for chunk in chunks:
        key = _norm(chunk)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(chunk)

    return out


def _find_best_chunk(
    chunks: list[str],
    required_names: list[str],
    preferred_cues: Iterable[str] | None = None,
) -> str | None:
    candidates: list[str] = []

    for chunk in chunks:
        if _is_report_centric(chunk):
            continue
        if not all(_contains_name(chunk, name) for name in required_names):
            continue
        candidates.append(chunk)

    if not candidates:
        return None

    if preferred_cues:
        preferred = [c for c in candidates if _has_any(c, preferred_cues)]
        if preferred:
            candidates = preferred

    candidates.sort(key=lambda c: (len(c), c))
    return candidates[0]


def _add_rel(
    rels: list[ExtractedRelationship],
    seen: set[tuple[str, str, str, str, str]],
    *,
    source_type: str,
    source_name: str,
    relationship_type: str,
    target_type: str,
    target_name: str,
    evidence: str,
    context: str | None = None,
    confidence: str = "medium",
) -> None:
    key = (
        _norm(source_type),
        _norm(source_name),
        _norm(relationship_type),
        _norm(target_type),
        _norm(target_name),
    )
    if key in seen:
        return

    cleaned_evidence = _clean_rel_text(evidence)
    cleaned_context = _clean_rel_text(context)

    if not cleaned_evidence and not cleaned_context:
        return

    seen.add(key)
    rels.append(
        ExtractedRelationship(
            source_type=source_type,
            source_name=source_name,
            relationship_type=relationship_type,
            target_type=target_type,
            target_name=target_name,
            evidence=cleaned_evidence or "",
            context=cleaned_context,
            confidence=confidence,
        )
    )


def _infer_delivery_direction(chunk: str, left_name: str, right_name: str) -> tuple[str, str] | None:
    text = _norm(chunk)
    left = re.escape(_norm(left_name))
    right = re.escape(_norm(right_name))
    verbs = "|".join(re.escape(v) for v in DELIVERY_VERBS)

    directional_patterns = [
        (left_name, right_name, rf"{left}.{{0,120}}(?:{verbs}).{{0,120}}{right}"),
        (right_name, left_name, rf"{right}.{{0,120}}(?:{verbs}).{{0,120}}{left}"),
        (left_name, right_name, rf"{left}.{{0,100}}(?:using|used|leveraged|employed).{{0,40}}(?:to )?(?:{verbs}).{{0,120}}{right}"),
        (right_name, left_name, rf"{right}.{{0,100}}(?:using|used|leveraged|employed).{{0,40}}(?:to )?(?:{verbs}).{{0,120}}{left}"),
        (right_name, left_name, rf"{left}.{{0,120}}(?:by|via|through|using|with).{{0,80}}{right}"),
        (left_name, right_name, rf"{right}.{{0,120}}(?:by|via|through|using|with).{{0,80}}{left}"),
    ]

    for source_name, target_name, pattern in directional_patterns:
        if re.search(pattern, text):
            return source_name, target_name

    if _has_any(text, DELIVERY_VERBS):
        return None

    return None


def build_relationships_after_verification(
    bundle: StixBundleInput,
    document_text: str | None = None,
) -> StixBundleInput:
    existing_relationships = list(getattr(bundle, "relationships", []) or [])
    relationships: list[ExtractedRelationship] = []
    seen: set[tuple[str, str, str, str, str]] = set()

    for relationship in existing_relationships:
        _add_rel(
            relationships,
            seen,
            source_type=relationship.source_type,
            source_name=relationship.source_name,
            relationship_type=relationship.relationship_type,
            target_type=relationship.target_type,
            target_name=relationship.target_name,
            evidence=relationship.evidence,
            context=relationship.context,
            confidence=getattr(relationship, "confidence", "medium"),
        )

    malwares = _entity_list(bundle, "malwares", "malware")
    attack_patterns = _entity_list(bundle, "attack_patterns")
    threat_actors = _entity_list(bundle, "threat_actors")
    campaigns = _entity_list(bundle, "campaigns")

    for malware in malwares:
        for attack_pattern in attack_patterns:
            chunks = _supporting_chunks(document_text, malware, attack_pattern)
            evidence = _find_best_chunk(
                chunks,
                [malware.name, attack_pattern.name],
                preferred_cues=USE_VERBS,
            )

            if not evidence:
                continue

            _add_rel(
                relationships,
                seen,
                source_type="malware",
                source_name=malware.name,
                relationship_type="uses",
                target_type="attack-pattern",
                target_name=attack_pattern.name,
                evidence=evidence,
                context=f"{malware.name} is associated with the technique {attack_pattern.name}.",
                confidence="high" if _has_any(evidence, USE_VERBS) else "medium",
            )

    for i, left in enumerate(malwares):
        for right in malwares[i + 1:]:
            chunks = _supporting_chunks(document_text, left, right)
            joint_chunk = _find_best_chunk(
                chunks,
                [left.name, right.name],
                preferred_cues=DELIVERY_VERBS,
            )

            if joint_chunk:
                direction = _infer_delivery_direction(joint_chunk, left.name, right.name)
                if direction:
                    source_name, target_name = direction
                    _add_rel(
                        relationships,
                        seen,
                        source_type="malware",
                        source_name=source_name,
                        relationship_type="delivers",
                        target_type="malware",
                        target_name=target_name,
                        evidence=joint_chunk,
                        context=f"{source_name} is used to deliver or execute {target_name}.",
                        confidence="high",
                    )
                    continue

            related_chunk = _find_best_chunk(
                chunks,
                [left.name, right.name],
                preferred_cues=EXPLICIT_RELATED_CUES,
            )
            if related_chunk and _has_any(related_chunk, EXPLICIT_RELATED_CUES):
                if _norm(left.name) <= _norm(right.name):
                    source_name, target_name = left.name, right.name
                else:
                    source_name, target_name = right.name, left.name

                _add_rel(
                    relationships,
                    seen,
                    source_type="malware",
                    source_name=source_name,
                    relationship_type="related-to",
                    target_type="malware",
                    target_name=target_name,
                    evidence=related_chunk,
                    context=f"{source_name} and {target_name} are explicitly linked in the source material.",
                    confidence="medium",
                )

    for threat_actor in threat_actors:
        for malware in malwares:
            chunks = _supporting_chunks(document_text, threat_actor, malware)
            evidence = _find_best_chunk(
                chunks,
                [threat_actor.name, malware.name],
                preferred_cues=USE_VERBS,
            )
            if not evidence:
                continue

            _add_rel(
                relationships,
                seen,
                source_type="threat-actor",
                source_name=threat_actor.name,
                relationship_type="uses",
                target_type="malware",
                target_name=malware.name,
                evidence=evidence,
                context=f"{threat_actor.name} is associated with the use of {malware.name}.",
                confidence="high" if _has_any(evidence, USE_VERBS) else "medium",
            )

    for threat_actor in threat_actors:
        for campaign in campaigns:
            chunks = _supporting_chunks(document_text, threat_actor, campaign)
            evidence = _find_best_chunk(
                chunks,
                [threat_actor.name, campaign.name],
                preferred_cues=ATTRIBUTION_CUES,
            )
            if not evidence:
                continue

            _add_rel(
                relationships,
                seen,
                source_type="threat-actor",
                source_name=threat_actor.name,
                relationship_type="attributed-to",
                target_type="campaign",
                target_name=campaign.name,
                evidence=evidence,
                context=f"{threat_actor.name} is explicitly linked to {campaign.name}.",
                confidence="high" if _has_any(evidence, ATTRIBUTION_CUES) else "medium",
            )

    for campaign in campaigns:
        for malware in malwares:
            chunks = _supporting_chunks(document_text, campaign, malware)
            evidence = _find_best_chunk(
                chunks,
                [campaign.name, malware.name],
                preferred_cues=USE_VERBS,
            )
            if not evidence:
                continue

            _add_rel(
                relationships,
                seen,
                source_type="campaign",
                source_name=campaign.name,
                relationship_type="uses",
                target_type="malware",
                target_name=malware.name,
                evidence=evidence,
                context=f"{campaign.name} is associated with the use of {malware.name}.",
                confidence="high" if _has_any(evidence, USE_VERBS) else "medium",
            )

    bundle.relationships = relationships
    return bundle