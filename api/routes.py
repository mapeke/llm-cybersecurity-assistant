from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import logging

# Import project modules
from utils.threat_analyzer import get_threat_analyzer
from integrations.wazuh.client import get_wazuh_client
from integrations.splunk.client import get_splunk_client

# Set up logging
logger = logging.getLogger(__name__)

# Create API routers
router = APIRouter(prefix="/api", tags=["cybersecurity"])

# ----- Model definitions -----

class QueryRequest(BaseModel):
    """Model for text query requests"""
    query: str
    context: Optional[Dict[str, Any]] = None

class AlertRequest(BaseModel):
    """Model for alert analysis requests"""
    alert_data: Dict[str, Any]
    source: str = "wazuh"  # Default source

class SecurityPolicyRequest(BaseModel):
    """Model for security policy generation requests"""
    policy_type: str
    organization_info: Optional[Dict[str, Any]] = None

class RemediationRequest(BaseModel):
    """Model for remediation steps requests"""
    threat_type: str

class QueryResponse(BaseModel):
    """Model for query responses"""
    answer: str
    confidence: float
    references: Optional[List[str]] = None

class RemediationResponse(BaseModel):
    """Model for remediation responses"""
    steps: List[str]

class SecurityPolicyResponse(BaseModel):
    """Model for security policy responses"""
    policy_type: str
    policy_content: str
    confidence: float

class InsightsResponse(BaseModel):
    """Model for security insights responses"""
    summary: str
    wazuh_insights: Optional[str] = None
    splunk_insights: Optional[str] = None
    recommendations: List[str]

# ----- API endpoints -----

@router.post("/query", response_model=QueryResponse)
async def process_query(request: QueryRequest):
    """Process a cybersecurity text query"""
    try:
        analyzer = get_threat_analyzer()
        response = analyzer.analyze_text_query(request.query)
        return response
    except Exception as e:
        logger.error(f"Error processing query: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error processing query: {str(e)}")

@router.post("/alert/analyze", response_model=QueryResponse)
async def analyze_alert(request: AlertRequest):
    """Analyze a security alert from an integrated tool"""
    try:
        analyzer = get_threat_analyzer()
        
        if request.source.lower() == "wazuh":
            response = analyzer.analyze_wazuh_alert(request.alert_data)
        elif request.source.lower() == "splunk":
            response = analyzer.analyze_splunk_event(request.alert_data)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported alert source: {request.source}")
            
        return response
    except Exception as e:
        logger.error(f"Error analyzing alert: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error analyzing alert: {str(e)}")

@router.post("/remediation", response_model=RemediationResponse)
async def get_remediation(request: RemediationRequest):
    """Get remediation steps for a specific threat type"""
    try:
        analyzer = get_threat_analyzer()
        steps = analyzer.generate_remediation_steps(request.threat_type)
        return {"steps": steps}
    except Exception as e:
        logger.error(f"Error generating remediation steps: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error generating remediation steps: {str(e)}")

@router.post("/policy/generate", response_model=SecurityPolicyResponse)
async def generate_policy(request: SecurityPolicyRequest):
    """Generate a security policy of the specified type"""
    try:
        analyzer = get_threat_analyzer()
        policy = analyzer.generate_security_policy(request.policy_type)
        return policy
    except Exception as e:
        logger.error(f"Error generating security policy: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error generating security policy: {str(e)}")

@router.get("/insights", response_model=InsightsResponse)
async def get_security_insights(hours_back: int = Query(24, ge=1, le=168)):
    """Get security insights from integrated tools"""
    try:
        analyzer = get_threat_analyzer()
        insights = analyzer.get_recent_security_insights(hours_back=hours_back)
        return insights
    except Exception as e:
        logger.error(f"Error getting security insights: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error getting security insights: {str(e)}")

@router.get("/wazuh/alerts")
async def get_wazuh_alerts(limit: int = Query(10, ge=1, le=100)):
    """Get recent alerts from Wazuh"""
    try:
        wazuh_client = get_wazuh_client()
        if not wazuh_client:
            raise HTTPException(status_code=503, detail="Wazuh integration not configured")
        
        alerts = wazuh_client.get_alerts(limit=limit)
        return {"alerts": alerts}
    except Exception as e:
        logger.error(f"Error getting Wazuh alerts: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error getting Wazuh alerts: {str(e)}")

@router.get("/splunk/events")
async def get_splunk_events(limit: int = Query(10, ge=1, le=100), hours_back: int = Query(24, ge=1, le=168)):
    """Get recent security events from Splunk"""
    try:
        splunk_client = get_splunk_client()
        if not splunk_client:
            raise HTTPException(status_code=503, detail="Splunk integration not configured")
        
        events = splunk_client.get_security_events(hours_back=hours_back, max_count=limit)
        return {"events": events}
    except Exception as e:
        logger.error(f"Error getting Splunk events: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error getting Splunk events: {str(e)}")

@router.get("/education/answer")
async def answer_education_question(question: str = Query(..., min_length=5)):
    """Answer employee questions about cybersecurity best practices"""
    try:
        analyzer = get_threat_analyzer()
        answer = analyzer.answer_security_question(question)
        return {"answer": answer}
    except Exception as e:
        logger.error(f"Error answering question: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error answering question: {str(e)}")