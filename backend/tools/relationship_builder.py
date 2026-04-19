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

ATTRIBUTION_VERBS = (
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


def _norm(value):
    return " ".join(value.strip().lower().split())

def _text(*parts: str | None):
    return " ".join(part for part in parts if part).strip()

def _contains_name(text, name) -> bool:
    return _norm(name) in _norm(text)

def _has_any(text, phrases: tuple[str, ...]) -> bool:
    norm_text = _norm(text)
    return any(phrase in norm_text for phrase in phrases)

def _is_report_centric(text) -> bool:
    norm_text = _norm(text)
    if norm_text in GENERIC_RELATIONSHIP_BAD_TEXT:
        return True
    return any(phrase in norm_text for phrase in REPORT_CENTRIC_PHRASES)

def _clean_rel_text(text):
    if not text:
        return None
    cleaned = " ".join(text.strip().split())
    if not cleaned:
        return None
    if _is_report_centric(cleaned):
        return None
    
    return str(cleaned)


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

    evidence = _clean_rel_text(evidence) or ""
    context = _clean_rel_text(context)

    seen.add(key)
    rels.append(
        ExtractedRelationship(
            source_type = source_type,
            source_name = source_name,
            relationship_type = relationship_type,
            target_type = target_type,
            target_name = target_name,
            evidence = evidence,
            context = context,
            confidence = confidence,
        )
    )


def build_relationships_after_verification(bundle: StixBundleInput) -> StixBundleInput:
    existing_relationships = list(getattr(bundle, "relationships", []) or [])
    relationships: list[ExtractedRelationship] = []
    seen: set[tuple[str, str, str, str, str]] = set()

    for relationship in existing_relationships:
        _add_rel(
            relationships,
            seen,
            source_type = relationship.source_type,
            source_name = relationship.source_name,
            relationship_type = relationship.relationship_type,
            target_type = relationship.target_type,
            target_name = relationship.target_name,
            evidence = relationship.evidence,
            context = relationship.context,
            confidence = relationship.confidence,
        )

    malwares = list(getattr(bundle, "malwares", []) or [])
    attack_patterns = list(getattr(bundle, "attack_patterns", []) or [])
    threat_actors = list(getattr(bundle, "threat_actors", []) or [])
    campaigns = list(getattr(bundle, "campaigns", []) or [])

    for malware in malwares:
        malware_text = _text(malware.evidence, malware.context)

        for ap in attack_patterns:
            ap_text = _text(ap.evidence, ap.context)

            if _is_report_centric(malware_text) and _is_report_centric(ap_text):
                continue

            if _contains_name(malware_text, ap.name) or _contains_name(ap_text, malware.name):
                evidence = _clean_rel_text(ap.evidence) or _clean_rel_text(malware.evidence)
                context = _clean_rel_text(ap.context) or _clean_rel_text(malware.context)

                if not evidence and not context:
                    continue

                _add_rel(
                    relationships,
                    seen,
                    source_type = "malware",
                    source_name = malware.name,
                    relationship_type = "uses",
                    target_type = "attack-pattern",
                    target_name = ap.name,
                    evidence = evidence or "",
                    context = context,
                    confidence = "high",
                )

    for i, left in enumerate(malwares):
        left_text = _text(left.evidence, left.context)

        for right in malwares[i + 1 :]:
            right_text = _text(right.evidence, right.context)

            left_mentions_right = _contains_name(left_text, right.name)
            right_mentions_left = _contains_name(right_text, left.name)

            left_delivers_right = left_mentions_right and _has_any(left_text, DELIVERY_VERBS)
            right_delivers_left = right_mentions_left and _has_any(right_text, DELIVERY_VERBS)

            # A -> delivers -> B
            if left_delivers_right and not right_delivers_left:
                evidence = _clean_rel_text(left.evidence)
                context = _clean_rel_text(left.context)
                if evidence or context:
                    _add_rel(
                        relationships,
                        seen,
                        source_type = "malware",
                        source_name = left.name,
                        relationship_type = "delivers",
                        target_type = "malware",
                        target_name = right.name,
                        evidence = evidence or "",
                        context = context,
                        confidence = "high",
                    )

                continue

            # B -> delivers -> A
            if right_delivers_left and not left_delivers_right:
                evidence = _clean_rel_text(right.evidence)
                context = _clean_rel_text(right.context)
                if evidence or context:
                    _add_rel(
                        relationships,
                        seen,
                        source_type = "malware",
                        source_name = right.name,
                        relationship_type = "delivers",
                        target_type = "malware",
                        target_name = left.name,
                        evidence = evidence or "",
                        context = context,
                        confidence = "high",
                    )

                continue

            # if both directions look like delivery, prefer the stronger side.
            if left_delivers_right and right_delivers_left:
                left_score = sum(verb in _norm(left_text) for verb in DELIVERY_VERBS)
                right_score = sum(verb in _norm(right_text) for verb in DELIVERY_VERBS)

                if left_score >= right_score:
                    evidence = _clean_rel_text(left.evidence)
                    context = _clean_rel_text(left.context)

                    source_name, target_name = left.name, right.name
                else:
                    evidence = _clean_rel_text(right.evidence)
                    context = _clean_rel_text(right.context)

                    source_name, target_name = right.name, left.name

                if evidence or context:
                    _add_rel(
                        relationships,
                        seen,
                        source_type = "malware",
                        source_name = source_name,
                        relationship_type = "delivers",
                        target_type = "malware",
                        target_name = target_name,
                        evidence = evidence or "",
                        context = context,
                        confidence = "medium",
                    )

                continue

            # only create related-to if there is an explicit
            combined_text = _text(left.evidence, left.context, right.evidence, right.context)
            if _is_report_centric(combined_text):
                continue

            if (left_mentions_right or right_mentions_left) and _has_any(combined_text, EXPLICIT_RELATED_CUES):
                left_name = _norm(left.name)
                right_name = _norm(right.name)

                if left_name <= right_name:
                    source_name, target_name = left.name, right.name
                    evidence = _clean_rel_text(left.evidence) or _clean_rel_text(right.evidence)
                    context = _clean_rel_text(left.context) or _clean_rel_text(right.context)
                else:
                    source_name, target_name = right.name, left.name
                    evidence = _clean_rel_text(right.evidence) or _clean_rel_text(left.evidence)
                    context = _clean_rel_text(right.context) or _clean_rel_text(left.context)

                if evidence or context:
                    _add_rel(
                        relationships,
                        seen,
                        source_type = "malware",
                        source_name = source_name,
                        relationship_type = "related-to",
                        target_type = "malware",
                        target_name = target_name,
                        evidence = evidence or "",
                        context = context,
                        confidence = "medium",
                    )

    for threat_actor in threat_actors:
        threat_actor_text = _text(threat_actor.evidence, threat_actor.context)

        if _is_report_centric(threat_actor_text):
            continue

        for malware in malwares:
            if _contains_name(threat_actor_text, malware.name):
                evidence = _clean_rel_text(threat_actor.evidence)
                context = _clean_rel_text(threat_actor.context)

                if not evidence and not context:
                    continue

                _add_rel(
                    relationships,
                    seen,
                    source_type = "threat-actor",
                    source_name = threat_actor.name,
                    relationship_type = "uses",
                    target_type = "malware",
                    target_name = malware.name,
                    evidence = evidence or "",
                    context = context,
                    confidence = "medium",
                )

    for threat_actor in threat_actors:
        threat_actor_text = _text(threat_actor.evidence, threat_actor.context)

        if _is_report_centric(threat_actor_text):
            continue

        for campaign in campaigns:
            if _contains_name(threat_actor_text, campaign.name):
                evidence = _clean_rel_text(threat_actor.evidence)
                context = _clean_rel_text(threat_actor.context)

                if not evidence and not context:
                    continue

                _add_rel(
                    relationships,
                    seen,
                    source_type = "threat-actor",
                    source_name = threat_actor.name,
                    relationship_type = "attributed-to",
                    target_type = "campaign",
                    target_name = campaign.name,
                    evidence = evidence or "",
                    context = context,
                    confidence = "medium",
                )

    # campaign -> uses -> malware
    for campaign in campaigns:
        campaign_text = _text(campaign.evidence, campaign.context)

        if _is_report_centric(campaign_text):
            continue

        for malware in malwares:
            if _contains_name(campaign_text, malware.name):
                evidence = _clean_rel_text(campaign.evidence)
                context = _clean_rel_text(campaign.context)

                if not evidence and not context:
                    continue

                _add_rel(
                    relationships,
                    seen,
                    source_type = "campaign",
                    source_name = campaign.name,
                    relationship_type = "uses",
                    target_type = "malware",
                    target_name = malware.name,
                    evidence = evidence or "",
                    context = context,
                    confidence = "medium",
                )

    bundle.relationships = relationships
    
    return bundle