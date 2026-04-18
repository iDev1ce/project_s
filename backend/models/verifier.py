from pydantic import BaseModel, ConfigDict, Field
from typing import List, Literal, Optional

from src.models.extractor import ExtractedDomain, StixBundleInput

ReviewAction = Literal["keep", "correct", "remove", "add", "flag"]
ConfidenceLevel = Literal["high", "medium", "low"]

ReviewItemType = Literal[
    "hash",
    "ipv4",
    "domain",
    "url",
    "email",
    "malware",
    "attack_pattern",
    "threat_actor",
    "campaign",
    "tool",
    "software",
    "group",
    "mitre_mapping",
    "other",
]

MitreObjectType = Literal[
    "technique",
    "sub-technique",
    "tactic",
    "group",
    "software",
    "campaign",
]

class VerifiedDomain(ExtractedDomain):
    role: Literal[
        "malicious_infrastructure",
        "phishing_infrastructure",
        "payload_delivery",
        "c2",
        "exfiltration",
        "victim_or_target",
        "benign_third_party",
        "vendor_or_research_source",
        "news_or_reference_source",
        "law_enforcement_or_public_org",
        "unknown",
    ]
    confidence: Literal["high", "medium", "low"]
    decision: Literal[
        "export_indicator",
        "keep_context_only",
        "flag_for_review",
        "drop",
    ]

class VerifiedBundleInput(StixBundleInput):
    domains: List[VerifiedDomain] = Field(default_factory=list)

class ReviewNote(BaseModel):
    action: ReviewAction
    item_type: ReviewItemType
    value: str
    reason: str
    evidence: str
    context: Optional[str] = None
    original_value: Optional[str] = None

    model_config = ConfigDict(extra="forbid")


class LowConfidenceItem(BaseModel):
    item_type: ReviewItemType
    value: str
    reason: str
    evidence: str
    confidence: ConfidenceLevel = "low"
    context: Optional[str] = None

    model_config = ConfigDict(extra="forbid")


class MitreAlignmentNote(BaseModel):
    source_value: str
    action: Literal["mapped", "corrected", "removed", "ambiguous", "flagged"]
    attack_object_type: MitreObjectType
    attack_id: Optional[str] = None
    attack_name: Optional[str] = None
    confidence: ConfidenceLevel
    reason: str
    evidence: str
    original_mapping: Optional[str] = None

    model_config = ConfigDict(extra="forbid")


class SaveVerifiedBundleInput(BaseModel):
    bundle: VerifiedBundleInput
    original_file_path: str
    review_notes: List[ReviewNote] = Field(default_factory=list)
    low_confidence_items: List[LowConfidenceItem] = Field(default_factory=list)
    mitre_alignment_notes: List[MitreAlignmentNote] = Field(default_factory=list)
    quality_score: int = Field(ge=1, le=10)
    reviewer_summary: Optional[str] = None

    model_config = ConfigDict(extra="forbid")