"""
REST API for Threat Modeling Tool
FastAPI endpoints with API key authentication
"""

from fastapi import FastAPI, Depends, HTTPException, status, Header, Request, Response
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, PlainTextResponse
from sqlalchemy.orm import Session
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime
import anthropic
import os

from models import (
    Organization, User, APIKey, AuditLog, APIUsageLog, 
    ThreatAssessment, UsageStats
)
from database import get_db, engine
from auth import SessionManager, SAMLAuthHandler


# Initialize FastAPI
app = FastAPI(
    title="AI Threat Modeling API",
    description="Enterprise-grade threat modeling API with AI-powered analysis",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Key authentication
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# Pydantic models for API requests/responses
class ThreatModelingRequest(BaseModel):
    project_name: str = Field(..., description="Name of the project")
    system_description: str = Field(..., description="Description of the system to analyze")
    framework: str = Field(..., description="Threat modeling framework (STRIDE, MITRE ATT&CK, PASTA, etc.)")
    risk_type: Optional[str] = Field(None, description="Type of risk assessment (Agentic AI, Model Risk, etc.)")
    company_name: Optional[str] = Field(None, description="Company name for report branding")
    additional_context: Optional[Dict[str, Any]] = Field(None, description="Additional context for analysis")


class ThreatModelingResponse(BaseModel):
    assessment_id: int
    project_name: str
    framework: str
    status: str
    report: str
    report_html: Optional[str]
    report_metadata: Optional[Dict[str, Any]]
    created_at: datetime


class APIKeyResponse(BaseModel):
    id: int
    name: str
    key_prefix: str
    scopes: List[str]
    is_active: bool
    created_at: datetime
    expires_at: Optional[datetime]


class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    full_name: Optional[str]
    role: str
    is_org_admin: bool
    organization_id: int
    created_at: datetime
    last_login: Optional[datetime]


class OrganizationResponse(BaseModel):
    id: int
    name: str
    slug: str
    max_users: int
    max_api_calls_per_month: int
    created_at: datetime


class AuditLogResponse(BaseModel):
    id: int
    user_email: Optional[str]
    action: str
    resource_type: Optional[str]
    description: Optional[str]
    status: str
    timestamp: datetime
    ip_address: Optional[str]


class UsageStatsResponse(BaseModel):
    total_assessments: int
    total_api_calls: int
    total_users: int
    active_users: int
    storage_used_gb: float
    assessments_by_framework: Optional[Dict[str, int]]
    api_calls_by_endpoint: Optional[Dict[str, int]]


# Startup initialization
@app.on_event("startup")
async def on_startup():
    secret = os.getenv("JWT_SECRET_KEY")
    if secret:
        SessionManager.init_secret_key(secret)
    else:
        # Fallback weak secret for dev only
        SessionManager.init_secret_key("dev-secret-change-me")


# Dependency to get current API key and user
async def get_current_api_key(
    api_key: str = Depends(api_key_header),
    db: Session = Depends(get_db)
) -> APIKey:
    """Validate API key and return the APIKey object"""
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key is missing"
        )
    
    # Hash the provided key
    key_hash = APIKey.hash_key(api_key)
    
    # Find the API key in database
    db_api_key = db.query(APIKey).filter(
        APIKey.key_hash == key_hash,
        APIKey.is_active == True
    ).first()
    
    if not db_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    # Check if expired
    if db_api_key.expires_at and db_api_key.expires_at < datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has expired"
        )
    
    # Update last used
    db_api_key.last_used_at = datetime.utcnow()
    db.commit()
    
    return db_api_key


async def get_current_user(
    api_key: APIKey = Depends(get_current_api_key),
    db: Session = Depends(get_db)
) -> User:
    """Get the user associated with the API key"""
    user = db.query(User).filter(
        User.id == api_key.user_id,
        User.is_active == True
    ).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    return user


def require_scope(required_scope: str):
    """Dependency to check if API key has required scope"""
    def check_scope(api_key: APIKey = Depends(get_current_api_key)):
        if not api_key.scopes or required_scope not in api_key.scopes:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key does not have required scope: {required_scope}"
            )
        return api_key
    return check_scope


async def log_api_usage(
    request: Request,
    api_key: APIKey,
    status_code: int,
    response_time_ms: int,
    db: Session
):
    """Log API usage for analytics and rate limiting"""
    usage_log = APIUsageLog(
        api_key_id=api_key.id,
        endpoint=str(request.url.path),
        method=request.method,
        status_code=status_code,
        response_time_ms=response_time_ms,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    db.add(usage_log)
    db.commit()


# API Endpoints

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.post("/api/v1/threat-modeling", response_model=ThreatModelingResponse)
async def create_threat_assessment(
    request: Request,
    threat_request: ThreatModelingRequest,
    user: User = Depends(get_current_user),
    api_key: APIKey = Depends(require_scope("threat_modeling:write")),
    db: Session = Depends(get_db)
):
    """Create a new threat assessment using AI"""
    start_time = datetime.utcnow()
    
    try:
        # Initialize Anthropic client
        anthropic_api_key = os.getenv("ANTHROPIC_API_KEY")
        if not anthropic_api_key:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="AI service not configured"
            )
        
        client = anthropic.Anthropic(api_key=anthropic_api_key)
        
        # Build prompt for threat modeling
        prompt = f"""Generate a comprehensive threat model for the following system:

Project: {threat_request.project_name}
Framework: {threat_request.framework}
Risk Type: {threat_request.risk_type or 'General'}

System Description:
{threat_request.system_description}

Please provide:
1. Identified threats based on {threat_request.framework} framework
2. Risk assessment and prioritization
3. Attack scenarios
4. Mitigation recommendations
5. Compliance considerations
"""
        
        # Call Claude AI
        message = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=4000,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        report = message.content[0].text
        
        # Create threat assessment record
        assessment = ThreatAssessment(
            organization_id=user.organization_id,
            user_id=user.id,
            project_name=threat_request.project_name,
            framework=threat_request.framework,
            risk_type=threat_request.risk_type,
            system_description=threat_request.system_description,
            assessment_report=report,
            status="completed",
            report_metadata={
                "company_name": threat_request.company_name,
                "generated_via": "API",
                "model": "claude-3-5-sonnet-20241022"
            }
        )
        db.add(assessment)
        
        # Log audit event
        audit_log = AuditLog(
            user_id=user.id,
            user_email=user.email,
            organization_id=user.organization_id,
            action="threat_assessment.create",
            resource_type="ThreatAssessment",
            resource_id=assessment.id,
            description=f"Created threat assessment via API: {threat_request.project_name}",
            status="success",
            metadata={
                "framework": threat_request.framework,
                "risk_type": threat_request.risk_type,
                "api_key_id": api_key.id
            },
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
        db.add(audit_log)
        
        db.commit()
        db.refresh(assessment)
        
        # Log API usage
        response_time = int((datetime.utcnow() - start_time).total_seconds() * 1000)
        await log_api_usage(request, api_key, 200, response_time, db)
        
        return ThreatModelingResponse(
            assessment_id=assessment.id,
            project_name=assessment.project_name,
            framework=assessment.framework,
            status=assessment.status,
            report=assessment.assessment_report,
            report_html=assessment.report_html,
            report_metadata=assessment.report_metadata,
            created_at=assessment.created_at
        )
        
    except Exception as e:
        # Log error
        audit_log = AuditLog(
            user_id=user.id,
            user_email=user.email,
            organization_id=user.organization_id,
            action="threat_assessment.create",
            resource_type="ThreatAssessment",
            description="Failed to create threat assessment via API",
            status="error",
            error_message=str(e),
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
        db.add(audit_log)
        db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create threat assessment: {str(e)}"
        )


@app.get("/api/v1/threat-modeling/{assessment_id}", response_model=ThreatModelingResponse)
async def get_threat_assessment(
    assessment_id: int,
    user: User = Depends(get_current_user),
    api_key: APIKey = Depends(require_scope("threat_modeling:read")),
    db: Session = Depends(get_db)
):
    """Get a specific threat assessment"""
    assessment = db.query(ThreatAssessment).filter(
        ThreatAssessment.id == assessment_id,
        ThreatAssessment.organization_id == user.organization_id
    ).first()
    
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat assessment not found"
        )
    
    return ThreatModelingResponse(
        assessment_id=assessment.id,
        project_name=assessment.project_name,
        framework=assessment.framework,
        status=assessment.status,
        report=assessment.assessment_report,
        report_html=assessment.report_html,
        report_metadata=assessment.report_metadata,
        created_at=assessment.created_at
    )


@app.get("/api/v1/threat-modeling", response_model=List[ThreatModelingResponse])
async def list_threat_assessments(
    skip: int = 0,
    limit: int = 20,
    user: User = Depends(get_current_user),
    api_key: APIKey = Depends(require_scope("threat_modeling:read")),
    db: Session = Depends(get_db)
):
    """List all threat assessments for the organization"""
    assessments = db.query(ThreatAssessment).filter(
        ThreatAssessment.organization_id == user.organization_id
    ).order_by(ThreatAssessment.created_at.desc()).offset(skip).limit(limit).all()
    
    return [
        ThreatModelingResponse(
            assessment_id=a.id,
            project_name=a.project_name,
            framework=a.framework,
            status=a.status,
            report=a.assessment_report,
            report_html=a.report_html,
            report_metadata=a.report_metadata,
            created_at=a.created_at
        )
        for a in assessments
    ]


# Admin endpoints

@app.get("/api/v1/admin/users", response_model=List[UserResponse])
async def list_users(
    user: User = Depends(get_current_user),
    api_key: APIKey = Depends(require_scope("admin:users")),
    db: Session = Depends(get_db)
):
    """List all users in the organization (admin only)"""
    if not user.is_org_admin and user.role != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    users = db.query(User).filter(
        User.organization_id == user.organization_id
    ).all()
    
    return [
        UserResponse(
            id=u.id,
            email=u.email,
            username=u.username,
            full_name=u.full_name,
            role=u.role,
            is_org_admin=u.is_org_admin,
            organization_id=u.organization_id,
            created_at=u.created_at,
            last_login=u.last_login
        )
        for u in users
    ]


@app.get("/api/v1/admin/audit-logs", response_model=List[AuditLogResponse])
async def get_audit_logs(
    skip: int = 0,
    limit: int = 100,
    action: Optional[str] = None,
    user: User = Depends(get_current_user),
    api_key: APIKey = Depends(require_scope("admin:audit")),
    db: Session = Depends(get_db)
):
    """Get audit logs for the organization (admin only)"""
    if not user.is_org_admin and user.role != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    query = db.query(AuditLog).filter(
        AuditLog.organization_id == user.organization_id
    )
    
    if action:
        query = query.filter(AuditLog.action == action)
    
    logs = query.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit).all()
    
    return [
        AuditLogResponse(
            id=log.id,
            user_email=log.user_email,
            action=log.action,
            resource_type=log.resource_type,
            description=log.description,
            status=log.status,
            timestamp=log.timestamp,
            ip_address=log.ip_address
        )
        for log in logs
    ]


@app.get("/api/v1/admin/usage-stats", response_model=UsageStatsResponse)
async def get_usage_stats(
    user: User = Depends(get_current_user),
    api_key: APIKey = Depends(require_scope("admin:stats")),
    db: Session = Depends(get_db)
):
    """Get usage statistics for the organization (admin only)"""
    if not user.is_org_admin and user.role != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    # Get latest usage stats
    stats = db.query(UsageStats).filter(
        UsageStats.organization_id == user.organization_id
    ).order_by(UsageStats.created_at.desc()).first()
    
    if not stats:
        # Return empty stats if none exist
        return UsageStatsResponse(
            total_assessments=0,
            total_api_calls=0,
            total_users=0,
            active_users=0,
            storage_used_gb=0.0,
            assessments_by_framework={},
            api_calls_by_endpoint={}
        )
    
    return UsageStatsResponse(
        total_assessments=stats.total_assessments,
        total_api_calls=stats.total_api_calls,
        total_users=stats.total_users,
        active_users=stats.active_users,
        storage_used_gb=stats.storage_used_gb,
        assessments_by_framework=stats.assessments_by_framework,
        api_calls_by_endpoint=stats.api_calls_by_endpoint
    )


# ============== SAML SSO Endpoints ==============

def _get_org_by_slug(db: Session, org_slug: str) -> Organization:
    org = db.query(Organization).filter(Organization.slug == org_slug).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if not org.saml_enabled:
        raise HTTPException(status_code=400, detail="SAML not enabled for organization")
    return org


@app.get("/saml/metadata/{org_slug}", response_class=PlainTextResponse)
async def saml_metadata(org_slug: str, db: Session = Depends(get_db)):
    """
    Generate SAML Service Provider metadata XML
    Includes signing certificate if configured
    """
    from onelogin.saml2.settings import OneLogin_Saml2_Settings

    org = _get_org_by_slug(db, org_slug)
    handler = SAMLAuthHandler(org)
    
    try:
        settings = OneLogin_Saml2_Settings(settings=handler._build_saml_settings(), sp_validation_only=True)
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)
        
        if len(errors) > 0:
            raise HTTPException(
                status_code=500, 
                detail=f"SAML metadata validation errors: {', '.join(errors)}"
            )
        
        return PlainTextResponse(content=metadata, media_type="application/xml")
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate SAML metadata: {str(e)}"
        )


@app.get("/saml/login/{org_slug}")
async def saml_login(org_slug: str, request: Request, db: Session = Depends(get_db)):
    org = _get_org_by_slug(db, org_slug)
    handler = SAMLAuthHandler(org)
    # Build a minimal request dict for python3-saml
    req_data = {
        'https': request.url.scheme == 'https',
        'http_host': request.client.host if request.client else 'localhost',
        'server_port': request.url.port or (443 if request.url.scheme == 'https' else 80),
        'script_name': request.url.path,
        'get_data': dict(request.query_params),
        'post_data': {}
    }
    redirect_url = handler.initiate_login(req_data)
    return RedirectResponse(url=redirect_url)


@app.post("/saml/acs/{org_slug}")
async def saml_acs(org_slug: str, request: Request, db: Session = Depends(get_db)):
    org = _get_org_by_slug(db, org_slug)
    handler = SAMLAuthHandler(org)

    form = await request.form()
    req_data = {
        'https': request.url.scheme == 'https',
        'http_host': request.client.host if request.client else 'localhost',
        'server_port': request.url.port or (443 if request.url.scheme == 'https' else 80),
        'script_name': request.url.path,
        'get_data': dict(request.query_params),
        'post_data': dict(form),
        'ip_address': request.client.host if request.client else None,
        'user_agent': request.headers.get('user-agent')
    }

    user = handler.process_response(req_data, db)
    if not user:
        raise HTTPException(status_code=401, detail="SAML authentication failed")

    # Issue JWT and set HttpOnly cookie
    access = SessionManager.create_access_token(user)
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:8501")
    # Also include the token in query string to let Streamlit capture it server-side
    redirect_with_token = f"{frontend_url}?token={access}"
    resp = RedirectResponse(url=redirect_with_token)
    # 1 hour expiry cookie
    resp.set_cookie(
        key="access_token",
        value=access,
        httponly=True,
        secure=False,  # set True in production behind HTTPS
        samesite="lax",
        max_age=3600
    )
    return resp


@app.get("/saml/sls/{org_slug}")
@app.post("/saml/sls/{org_slug}")
async def saml_sls(org_slug: str, request: Request, db: Session = Depends(get_db)):
    """
    SAML Single Logout Service (SLS)
    Handles logout requests from IdP
    """
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    
    org = _get_org_by_slug(db, org_slug)
    handler = SAMLAuthHandler(org)
    
    # Build request dict
    if request.method == "POST":
        form = await request.form()
        post_data = dict(form)
    else:
        post_data = {}
    
    req_data = {
        'https': request.url.scheme == 'https',
        'http_host': request.client.host if request.client else 'localhost',
        'server_port': request.url.port or (443 if request.url.scheme == 'https' else 80),
        'script_name': request.url.path,
        'get_data': dict(request.query_params),
        'post_data': post_data
    }
    
    req = handler.prepare_request(req_data)
    auth = OneLogin_Saml2_Auth(req, handler.settings)
    
    # Process logout request
    url = auth.process_slo(delete_session_cb=lambda: None)
    errors = auth.get_errors()
    
    if errors:
        raise HTTPException(status_code=400, detail=f"SAML SLO error: {', '.join(errors)}")
    
    # Clear cookies and redirect
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:8501")
    resp = RedirectResponse(url=url or frontend_url)
    resp.delete_cookie("access_token")
    return resp


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
