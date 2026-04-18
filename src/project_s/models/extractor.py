from pydantic import BaseModel, ConfigDict, Field
from typing import List, Literal, Optional

class ExtractionBase(BaseModel):
    evidence: str = ""
    context: Optional[str] = None

    model_config = ConfigDict(extra="forbid")


class ExtractedHash(ExtractionBase):
    algorithm: Literal["MD5", "SHA-1", "SHA-256"]
    value: str


class ExtractedIPv4(ExtractionBase):
    value: str


class ExtractedDomain(ExtractionBase):
    value: str
    evidence: str = ""
    context: Optional[str] = None


class ExtractedMalware(ExtractionBase):
    name: str


class ExtractedAttackPattern(ExtractionBase):
    name: str


class ExtractedThreatActor(ExtractionBase):
    name: str


class ExtractedCampaign(ExtractionBase):
    name: str


class ExtractedRelationship(ExtractionBase):
    source_type: Literal[
        "indicator",
        "malware",
        "attack-pattern",
        "threat-actor",
        "campaign",
    ]
    source_name: str
    relationship_type: Literal[
        "uses",
        "delivers",
        "targets",
        "attributed-to",
        "indicates",
        "related-to",
    ]
    target_type: Literal[
        "indicator",
        "malware",
        "attack-pattern",
        "threat-actor",
        "campaign",
    ]
    target_name: str
    confidence: Literal["high", "medium", "low"] = "medium"


class StixBundleInput(BaseModel):
    file_hashes: List[ExtractedHash] = Field(default_factory=list)
    ipv4s: List[ExtractedIPv4] = Field(default_factory=list)
    domains: List[ExtractedDomain] = Field(default_factory=list)

    malwares: List[ExtractedMalware] = Field(default_factory=list)
    attack_patterns: List[ExtractedAttackPattern] = Field(default_factory=list)
    threat_actors: List[ExtractedThreatActor] = Field(default_factory=list)
    campaigns: List[ExtractedCampaign] = Field(default_factory=list)

    relationships: List[ExtractedRelationship] = Field(default_factory=list)

    report_title: Optional[str] = None
    description: Optional[str] = None

    model_config = ConfigDict(extra="forbid")