from pydantic import BaseModel, Field
from typing import List, Optional, Dict

class CVSSDataModel(BaseModel):
    """Schema for detailed CVSS data."""
    version: str
    vectorString: str
    baseScore: float
    accessVector: str
    accessComplexity: str
    authentication: str
    confidentialityImpact: str
    integrityImpact: str
    availabilityImpact: str

class CVSSMetricModel(BaseModel):
    """Schema for CVSS Metric, ensuring only one of V2 or V3 exists."""
    source: str
    type: str
    cvssData: CVSSDataModel
    baseSeverity: str
    exploitabilityScore: float
    impactScore: float
    acInsufInfo: bool
    obtainAllPrivilege: bool
    obtainUserPrivilege: bool
    obtainOtherPrivilege: bool
    userInteractionRequired: bool

class CPEMatchModel(BaseModel):
    """Schema for configuration CPE matches."""
    vulnerable: bool
    criteria: str
    matchCriteriaId: str

class ConfigurationNodeModel(BaseModel):
    """Schema for configuration nodes."""
    operator: str
    negate: bool
    cpeMatch: List[CPEMatchModel]

class ConfigurationModel(BaseModel):
    """Schema for overall configurations."""
    nodes: List[ConfigurationNodeModel]

class CVEModel(BaseModel):
    """Schema for storing validated CVE details."""
    id: str = Field(..., description="CVE ID")
    sourceIdentifier: str = Field(..., description="Source of CVE entry")
    published: str = Field(..., description="Date when CVE was published")
    lastModified: str = Field(..., description="Last modification date")
    vulnStatus: str = Field(..., description="Current vulnerability status")
    metrics: CVSSMetricModel = Field(..., description="CVSS scoring details")
    configurations: List[ConfigurationModel] = Field(..., description="Configuration data related to CVE")
