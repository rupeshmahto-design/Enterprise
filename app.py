"""
AI-Powered Threat Modeling Tool
Enterprise-grade threat assessment with PostgreSQL backend
"""

import os
import io
import base64
from typing import List
from datetime import datetime
from pathlib import Path
import json

import anthropic
import streamlit as st
from sqlalchemy.orm import Session

import admin_dashboard
from auth import PasswordAuth
from database import SessionLocal, init_db
from models import ThreatAssessment, User, Organization

# Initialize database tables and seed data on startup
try:
    init_db()
    # Seed initial admin user if database is empty
    db = SessionLocal()
    try:
        if db.query(Organization).count() == 0:
            from models import Organization
            org = Organization(
                name="Default Organization",
                slug="default",
                domain="example.com",
                saml_enabled=False,
                max_users=50
            )
            db.add(org)
            db.commit()
            db.refresh(org)
            
            # Create admin user
            admin = User(
                email="admin@example.com",
                username="admin",
                full_name="System Administrator",
                password_hash=PasswordAuth.hash_password("admin123"),
                role="super_admin",
                is_active=True,
                is_org_admin=True,
                organization_id=org.id
            )
            db.add(admin)
            db.commit()
            print("✅ Database initialized with default admin user")
    finally:
        db.close()
except Exception as e:
    print(f"Database initialization: {e}")

# Page configuration
st.set_page_config(
    page_title="AI Threat Modeling Tool",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for beautiful UI
st.markdown("""
    <style>
    * { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif; }
    .main { background: #f8fafc; }
    h1 { color: #0f172a !important; font-weight: 700 !important; }
    h2 { color: #1e293b !important; font-weight: 700 !important; border-bottom: 3px solid #3b82f6 !important; padding-bottom: 0.5rem !important; }
    .stButton>button { background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%) !important; color: white !important; border-radius: 8px !important; font-weight: 600 !important; border: none !important; }
    .stButton>button:hover { background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%) !important; }
    .framework-card { background: white !important; border: 2px solid #e2e8f0 !important; padding: 1.5rem !important; border-radius: 12px !important; margin: 1rem 0 !important; }
    .framework-card.selected { background: #eff6ff !important; border-color: #3b82f6 !important; }
    .upload-box { border: 3px dashed #3b82f6 !important; border-radius: 12px !important; padding: 2.5rem 2rem !important; text-align: center !important; background: linear-gradient(135deg, #eff6ff 0%, #f0f9ff 100%) !important; margin: 1rem 0 !important; }
    </style>
""", unsafe_allow_html=True)

# Session state defaults
if "user_id" not in st.session_state:
    st.session_state.user_id = None
if "user" not in st.session_state:
    st.session_state.user = None
if 'assessment_complete' not in st.session_state:
    st.session_state.assessment_complete = False
if 'threat_report' not in st.session_state:
    st.session_state.threat_report = None
if 'uploaded_files' not in st.session_state:
    st.session_state.uploaded_files = []

# Threat Modeling Frameworks
FRAMEWORKS = {
    "MITRE ATT&CK": {
        "description": "Comprehensive framework for understanding cyber adversary behavior",
        "focus": "Tactics, Techniques, and Procedures (TTPs)",
        "best_for": "Advanced threat modeling, APT analysis, comprehensive security assessments",
        "coverage": ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", 
                     "Credential Access", "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Impact"]
    },
    "STRIDE": {
        "description": "Microsoft's threat modeling methodology",
        "focus": "Six threat categories (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)",
        "best_for": "Software development, API security, application security",
        "coverage": ["Spoofing Identity", "Tampering with Data", "Repudiation", "Information Disclosure", 
                     "Denial of Service", "Elevation of Privilege"]
    },
    "PASTA": {
        "description": "Process for Attack Simulation and Threat Analysis",
        "focus": "Risk-centric approach with seven stages",
        "best_for": "Risk-based threat modeling, business-aligned security",
        "coverage": ["Define Objectives", "Define Technical Scope", "Application Decomposition", 
                     "Threat Analysis", "Vulnerability Analysis", "Attack Modeling", "Risk & Impact Analysis"]
    },
    "OCTAVE": {
        "description": "Operationally Critical Threat, Asset, and Vulnerability Evaluation",
        "focus": "Organizational risk assessment",
        "best_for": "Enterprise risk management, asset-based threat modeling",
        "coverage": ["Build Asset-Based Threat Profiles", "Identify Infrastructure Vulnerabilities", 
                     "Develop Security Strategy and Plans"]
    },
    "VAST": {
        "description": "Visual, Agile, and Simple Threat modeling",
        "focus": "Scalable threat modeling for agile development",
        "best_for": "DevSecOps, continuous threat modeling, large organizations",
        "coverage": ["Application Threat Models", "Operational Threat Models", "Infrastructure Models"]
    }
}

# Risk Focus Areas
RISK_AREAS = {
    "Agentic AI Risk": {
        "description": "Risks from autonomous AI agents and systems",
        "threats": [
            "Prompt injection and jailbreaking",
            "Unauthorized actions by autonomous agents",
            "Model hallucinations and incorrect decisions",
            "Data poisoning and training manipulation",
            "Agent-to-agent communication security",
            "Privilege escalation by AI agents",
            "Loss of human oversight and control"
        ]
    },
    "Model Risk": {
        "description": "Risks associated with AI/ML model deployment and operations",
        "threats": [
            "Model drift and degradation",
            "Adversarial attacks on models",
            "Model inversion and extraction",
            "Bias and fairness issues",
            "Model supply chain attacks",
            "Insufficient model validation",
            "Model versioning and rollback issues"
        ]
    },
    "Data Security Risk": {
        "description": "Risks related to data confidentiality, integrity, and availability",
        "threats": [
            "Data breaches and exfiltration",
            "Unauthorized access to sensitive data",
            "Data tampering and corruption",
            "Insufficient encryption",
            "Data residency violations",
            "PII exposure",
            "Data retention and disposal issues"
        ]
    },
    "Infrastructure Risk": {
        "description": "Risks in underlying technology infrastructure",
        "threats": [
            "Cloud misconfigurations",
            "Network vulnerabilities",
            "Container and orchestration risks",
            "API security weaknesses",
            "Insufficient monitoring",
            "Denial of service vulnerabilities",
            "Third-party integration risks"
        ]
    },
    "Compliance Risk": {
        "description": "Regulatory and compliance-related risks",
        "threats": [
            "GDPR violations",
            "PCI-DSS non-compliance",
            "HIPAA violations",
            "SOX control failures",
            "Industry-specific regulation gaps",
            "Audit trail insufficiencies",
            "Data sovereignty issues"
        ]
    }
}


def get_db_session() -> Session:
    return SessionLocal()


def load_user(db: Session) -> User | None:
    if st.session_state.user_id is None:
        return None
    return db.query(User).filter(User.id == st.session_state.user_id, User.is_active == True).first()


def extract_text_from_file(uploaded_file):
    """Extract text content from uploaded files"""
    try:
        file_extension = Path(uploaded_file.name).suffix.lower()
        if file_extension in ['.txt', '.md']:
            return uploaded_file.getvalue().decode('utf-8')
        else:
            return f"[{file_extension.upper()} Document: {uploaded_file.name}]"
    except Exception as e:
        return f"[Error reading {uploaded_file.name}: {str(e)}]"


def create_pdf_download(report_content, project_name):
    """Create a PDF download using ReportLab (pure Python, no system deps)"""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
    import re
    
    base = f"Threat_Assessment_{project_name.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}"
    pdf_filename = f"{base}.pdf"
    
    # Create PDF buffer
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.75*inch, bottomMargin=0.75*inch,
                           leftMargin=0.75*inch, rightMargin=0.75*inch)
    
    # Styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#1a202c'),
        spaceAfter=12,
        spaceBefore=6,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    heading1_style = ParagraphStyle(
        'CustomHeading1',
        parent=styles['Heading1'],
        fontSize=14,
        textColor=colors.HexColor('#2d3748'),
        spaceBefore=12,
        spaceAfter=6,
        fontName='Helvetica-Bold'
    )
    heading2_style = ParagraphStyle(
        'CustomHeading2',
        parent=styles['Heading2'],
        fontSize=11,
        textColor=colors.HexColor('#2c5282'),
        spaceBefore=8,
        spaceAfter=4,
        fontName='Helvetica-Bold'
    )
    body_style = ParagraphStyle(
        'CustomBody',
        parent=styles['BodyText'],
        fontSize=9,
        leading=11,
        alignment=TA_LEFT,
        spaceAfter=4
    )
    
    # Build content
    story = []
    
    # Title page
    story.append(Paragraph("Threat Assessment Report", title_style))
    story.append(Spacer(1, 0.15*inch))
    story.append(Paragraph(f"<b>Project:</b> {project_name}", body_style))
    story.append(Paragraph(f"<b>Date:</b> {datetime.now().strftime('%B %d, %Y')}", body_style))
    story.append(Spacer(1, 0.3*inch))
    
    # Parse markdown content
    lines = report_content.split('\n')
    current_table = []
    in_table = False
    
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        
        # Skip table separator lines (---|---|---)
        if re.match(r'^[\|\s\-:]+$', line) and '|' in line:
            i += 1
            continue
        
        # Empty lines
        if not line:
            if not in_table:
                story.append(Spacer(1, 0.08*inch))
            i += 1
            continue
        
        # Headers
        if line.startswith('# ') and not line.startswith('## '):
            if current_table:
                table_element = create_reportlab_table(current_table)
                if table_element:
                    story.append(table_element)
                current_table = []
                in_table = False
            story.append(Spacer(1, 0.15*inch))
            story.append(Paragraph(line[2:], title_style))
        elif line.startswith('## ') and not line.startswith('### '):
            if current_table:
                table_element = create_reportlab_table(current_table)
                if table_element:
                    story.append(table_element)
                current_table = []
                in_table = False
            story.append(Paragraph(line[3:], heading1_style))
        elif line.startswith('### '):
            if current_table:
                table_element = create_reportlab_table(current_table)
                if table_element:
                    story.append(table_element)
                current_table = []
                in_table = False
            story.append(Paragraph(line[4:], heading2_style))
        
        # Table rows
        elif '|' in line and line.count('|') >= 2:
            in_table = True
            cells = [cell.strip() for cell in line.split('|') if cell.strip()]
            if cells:  # Only add non-empty rows
                current_table.append(cells)
        
        # Regular text
        else:
            if in_table and current_table:
                table_element = create_reportlab_table(current_table)
                if table_element:
                    story.append(table_element)
                current_table = []
                in_table = False
            
            # Format inline markdown
            line = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', line)
            line = re.sub(r'`(.+?)`', r'<font face="Courier" size="8">\1</font>', line)
            # Escape special XML chars
            line = line.replace('&', '&amp;').replace('<b>', '<<<B>>>').replace('</b>', '<<</B>>>').replace('<font', '<<<FONT').replace('</font>', '<<</FONT>>>')
            line = line.replace('<<<B>>>', '<b>').replace('<<</B>>>', '</b>').replace('<<<FONT', '<font').replace('<<</FONT>>>', '</font>')
            
            try:
                story.append(Paragraph(line, body_style))
            except:
                # Fallback for problematic lines
                story.append(Paragraph(line.replace('<', '&lt;').replace('>', '&gt;'), body_style))
        
        i += 1
    
    # Add remaining table
    if current_table:
        table_element = create_reportlab_table(current_table)
        if table_element:
            story.append(table_element)
    
    # Build PDF
    try:
        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_filename, pdf_bytes, "application/pdf"
    except Exception as e:
        buffer.close()
        # Fallback to markdown
        return f"{base}.md", report_content, "text/markdown"


def create_reportlab_table(table_data):
    """Helper to create formatted table for ReportLab"""
    from reportlab.platypus import Table, TableStyle, Paragraph
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    
    if not table_data or len(table_data) < 1:
        return None
    
    # Wrap cells in Paragraphs for better text wrapping
    styles = getSampleStyleSheet()
    cell_style = styles['BodyText']
    cell_style.fontSize = 7
    cell_style.leading = 9
    
    wrapped_data = []
    for row in table_data:
        wrapped_row = []
        for cell in row:
            # Clean and wrap cell text
            cell_text = str(cell).strip()
            cell_text = cell_text.replace('**', '<b>').replace('**', '</b>')
            try:
                wrapped_row.append(Paragraph(cell_text, cell_style))
            except:
                wrapped_row.append(cell_text)
        wrapped_data.append(wrapped_row)
    
    # Calculate column widths based on content
    num_cols = len(wrapped_data[0]) if wrapped_data else 1
    available_width = 7 * inch  # Letter page width minus margins
    col_width = available_width / num_cols
    col_widths = [col_width] * num_cols
    
    # Create table with style
    table = Table(wrapped_data, colWidths=col_widths, repeatRows=1)
    
    style = TableStyle([
        # Header row
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2d3748')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
        ('TOPPADDING', (0, 0), (-1, 0), 6),
        # Body
        ('BACKGROUND', (0, 1), (-1, -1), colors.white),
        ('FONTSIZE', (0, 1), (-1, -1), 7),
        ('TOPPADDING', (0, 1), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
        # Grid
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e0')),
        # Alternate row colors
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')])
    ])
    
    table.setStyle(style)
    return table


def generate_threat_assessment(project_info, documents_content, framework, risk_areas, user: User, db: Session):
    """Generate comprehensive threat assessment using Claude"""
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key or api_key.startswith("sk-ant-api03-CHANGE"):
        raise RuntimeError("Missing Anthropic API key in .env (ANTHROPIC_API_KEY)")

    client = anthropic.Anthropic(api_key=api_key)
    
    # Comprehensive prompt with document evidence requirements
    prompt = f"""You are an expert cybersecurity consultant specializing in threat modeling and risk assessment. 
Perform a comprehensive threat assessment for the following project using the {framework} framework.

**PROJECT INFORMATION:**
- Project Name: {project_info['name']}
- Application Type: {project_info['app_type']}
- Deployment Model: {project_info['deployment']}
- Business Criticality: {project_info['criticality']}
- Compliance Requirements: {', '.join(project_info['compliance'])}
- Environment: {project_info['environment']}

**UPLOADED DOCUMENTATION:**
{documents_content}

**THREAT MODELING FRAMEWORK:** {framework}
{FRAMEWORKS[framework]['description']}

**SPECIFIC RISK FOCUS AREAS TO ASSESS:**
{chr(10).join([f"- {area}: {RISK_AREAS[area]['description']}" for area in risk_areas])}

**ASSESSMENT REQUIREMENTS - EVIDENCE-BASED ANALYSIS:**

Generate a professional threat assessment report with complete structure, extensive tables, and color-coded risk levels suitable for executive review.

**CRITICAL REQUIREMENT: Every finding, recommendation, and observation MUST include:**
1. **Document Reference:** Which uploaded document this observation is from
2. **Evidence Citation:** Specific quote or observation from the document
3. **Line Context:** Approximate location/section in the document
4. **Analysis:** How this evidence leads to the threat assessment finding
5. **Concrete Examples:** Specific examples from the documentation demonstrating the issue/risk

# EXECUTIVE SUMMARY

**Overall Risk Rating:** [CRITICAL/HIGH/MEDIUM/LOW]

[One paragraph describing assessment scope, methodology, and documents reviewed]

## Top 5 Critical Findings (with Document Evidence & Examples)

| Finding | Evidence Source (Doc) | Example from Docs | Risk Level | Business Impact | Timeline |
|---------|-----------------------|-------------------|-----------|-----------------|-----------|
| [Finding 1 with doc ref] | [Document: Name/Section] | [Specific example from doc] | CRITICAL | [Impact description] | Immediate (0-30 days) |
| [Finding 2 with doc ref] | [Document: Name/Section] | [Specific example from doc] | HIGH | [Impact description] | Short-term (30-90 days) |

## Key Recommendations Summary

| Priority | Count | Sample Actions |
|----------|-------|-----------------|
| P0 - CRITICAL | [count] | Immediate mitigations for critical risks |
| P1 - HIGH | [count] | High-priority security improvements |
| P2 - MEDIUM | [count] | Medium-term strengthening measures |

---

# THREAT MODELING ANALYSIS - {framework}

**Summary:** [2-3 sentence overview of the threat modeling analysis, the framework's approach, and key findings discovered during the analysis]

Comprehensive threat analysis organized by {framework} categories with risk scoring and mitigation paths, **with evidence citations and concrete examples from uploaded documentation**.

For each relevant category in {framework}, provide detailed analysis:

## [Category Name]

**Summary:** [1-2 sentences describing the threats found in this category and their overall risk level]

| Threat ID | Threat Description | Document Evidence | Example from Documentation | Likelihood | Impact | Risk Score | Recommended Mitigation |
|-----------|-------------------|-------------------|---------------------------|-----------|--------|-----------|----------------------|
| T001 | [threat description] | [Doc: Name, Section/Quote] | [Specific example from doc] | [1-5] | [1-5] | [score] | [mitigation] |

---

# SPECIALIZED RISK ASSESSMENTS

**Summary:** [2-3 sentences describing the selected risk focus areas, why they're important for this project, and the overall risk landscape across these areas]

{chr(10).join([f'''## {area}

**Summary:** [1-2 sentences describing the risk landscape for {area} based on the documentation review]

| Threat ID | Evidence Source (Doc) | Example from Docs | Threat | Likelihood | Impact | Risk Priority | Mitigation Strategy |
|-----------|-----------------------|-------------------|--------|-----------|--------|---------------|---------------------|
| T-{area[:3].upper()}-001 | [Doc: Section] | [Specific example] | [specific threat] | [1-5] | [1-5] | P0/P1/P2 | [specific action] |
''' for area in risk_areas])}

---

# COMPONENT-SPECIFIC THREAT ANALYSIS

**Summary:** [2-3 sentences describing the system architecture components analyzed and the overall security posture across different layers]

| Component | Document Evidence | Example from Docs | Critical Threats | Risk Level | Mitigation Approach |
|-----------|-------------------|-------------------|-----------------|-----------|---------------------|
| Frontend/UI | [Doc: Section] | [example from doc] | [threats] | CRITICAL/HIGH | [approach] |
| Backend/App | [Doc: Section] | [example from doc] | [threats] | CRITICAL/HIGH | [approach] |
| Database/Data | [Doc: Section] | [example from doc] | [threats] | CRITICAL/HIGH | [approach] |

---

# ATTACK SCENARIOS & KILL CHAINS

**Summary:** [2-3 sentences describing the most likely attack scenarios identified, how attackers might progress through the system, and the overall threat sophistication expected]

## Scenario 1: [Attack Title - Highest Risk Scenario from Document Evidence]

**Summary:** [1-2 sentences describing this specific attack scenario, the attacker profile, and expected impact]

| Kill Chain Phase | Document Evidence | Example from Docs | Description | Detection Window | Mitigation Strategy |
|-----------------|-------------------|-------------------|-------------|------------------|---------------------|
| Reconnaissance | [Doc: Section] | [example from doc] | [phase details] | [detection opportunity] | [mitigation] |
| Exploitation | [Doc: Section] | [example from doc] | [phase details] | [detection opportunity] | [mitigation] |
| Exfiltration | [Doc: Section] | [example from doc] | [phase details] | [detection opportunity] | [mitigation] |

---

# COMPREHENSIVE RISK MATRIX

**Summary:** [2-3 sentences explaining the risk scoring methodology, how likelihood and impact are calculated, and the overall risk distribution across findings]

## Risk Score Calculation

| Likelihood (L) | 1 - Rare | 2 - Unlikely | 3 - Possible | 4 - Likely | 5 - Very Likely |
|---|---|---|---|---|---|
| **5 - Catastrophic** | 5 | 10 | 15 | 20 | **25-CRITICAL** |
| **4 - Major** | 4 | 8 | 12 | **16-HIGH** | **20-CRITICAL** |
| **3 - Moderate** | 3 | 6 | **9-MEDIUM** | **12-HIGH** | **15-HIGH** |

## All Findings Risk Matrix

| Finding ID | Description | Likelihood | Impact | Risk Score | Risk Level | Priority | Owner | Remediation Timeline |
|----------|-------------|-----------|--------|-----------|-----------|----------|-------|----------------------|
| F001 | [critical finding] | [1-5] | [1-5] | [score] | **CRITICAL** | P0 | [owner] | 0-30 days |

---

# PRIORITIZED RECOMMENDATIONS

**Summary:** [2-3 sentences describing the remediation strategy, prioritization approach, and expected timeline for implementation]

## P0 - CRITICAL (Remediate in 0-30 days)

**These findings represent immediate threats requiring urgent action.**

| Rec ID | Recommendation | Current Risk | Risk Reduction | Implementation Steps | Required Effort | Owner | Target Completion |
|--------|---------------|--------------|----------------|---------------------|-----------------|-------|------------------|
| R001 | [action] | Critical | [% reduction] | [step 1, 2, 3...] | [effort estimate] | [owner] | [date] |

## P1 - HIGH (Remediate in 30-90 days)

**High-priority improvements that significantly reduce risk exposure.**

| Rec ID | Recommendation | Current Risk | Risk Reduction | Implementation Steps | Required Effort | Owner | Target Completion |
|--------|---------------|--------------|----------------|---------------------|-----------------|-------|------------------|
| R010 | [action] | High | [% reduction] | [step 1, 2, 3...] | [effort estimate] | [owner] | [date] |

---

# SECURITY CONTROLS MAPPING

**Summary:** [2-3 sentences describing the security controls framework used, how controls map to findings, and the overall control maturity]

| Control Category | Control Name | Implementation Status | Addresses Finding | Compliance Requirement | Timeline |
|-----------------|--------------|----------------------|-------------------|----------------------|----------|
| Preventive | [control] | [Not Started/In Progress/Implemented] | [F-ID] | [framework] | [timeline] |
| Detective | [control] | [Not Started/In Progress/Implemented] | [F-ID] | [framework] | [timeline] |

---

# COMPLIANCE CONSIDERATIONS

**Summary:** [2-3 sentences describing the compliance requirements, current gaps identified, and timeline for achieving compliance]

| Finding ID | Finding | Compliance Requirement | Compliance Gap | Required Evidence | Remediation Timeline |
|----------|---------|----------------------|----------------|------------------|---------------------|
{chr(10).join([f"| [F-ID] | [finding] | {req} | [gap description] | [evidence needed] | [timeline] |" for req in project_info['compliance']])}

---

# REFERENCES

**Threat Modeling Frameworks:**
- **{framework}** - {FRAMEWORKS[framework]['description']}
  - Focus: {FRAMEWORKS[framework]['focus']}
  - Coverage: {', '.join(FRAMEWORKS[framework]['coverage'][:3])}...

**Security Standards & Guidelines:**
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final) - Security and Privacy Controls for Information Systems and Organizations
- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/) - Top 10 Web Application Security Risks
- [MITRE ATT&CK Framework](https://attack.mitre.org/) - Adversary Tactics, Techniques, and Common Knowledge
- [CIS Critical Security Controls v8](https://www.cisecurity.org/controls/v8) - Critical Security Controls for Effective Cyber Defense
- [ISO/IEC 27001:2013](https://www.iso.org/standard/54534.html) - Information Security Management Systems Requirements

**Compliance Frameworks:**
{chr(10).join([f"- **{req}** - Regulatory compliance framework" for req in project_info['compliance']])}

**Risk Assessment Methodologies:**
- [CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document) - Common Vulnerability Scoring System
- [FAIR](https://www.fairinstitute.org/) - Factor Analysis of Information Risk
- [NIST Risk Management Framework (RMF)](https://csrc.nist.gov/projects/risk-management/about-rmf) - NIST Risk Management Framework

**Additional Resources:**
- [CERT Secure Coding Standards](https://wiki.sei.cmu.edu/confluence/display/seccode) - Carnegie Mellon SEI Secure Coding
- [SANS Top 25 Most Dangerous Software Errors](https://www.sans.org/top25-software-errors/) - SANS CWE Top 25
- [Cloud Security Alliance (CSA) Cloud Controls Matrix](https://cloudsecurityalliance.org/research/cloud-controls-matrix/) - CSA CCM
- [ENISA Threat Landscape Reports](https://www.enisa.europa.eu/topics/threat-risk-management/threats-and-trends) - European Union Agency for Cybersecurity

---

# DISCLAIMER

**AI-Generated Report Notice:**

This threat assessment report was generated using artificial intelligence (AI) technology powered by SecureAI. While the analysis incorporates industry-standard frameworks, best practices, and uploaded documentation, it should be considered as a preliminary assessment tool.

**Important Considerations:**
- This report is AI-generated and may contain inaccuracies, omissions, or misinterpretations
- All findings, risk ratings, and recommendations must be validated by qualified security professionals
- The assessment should be reviewed and supplemented with manual security analysis
- Implementation of any recommendations should be evaluated in the context of your specific environment
- This report does not replace professional security audits, penetration testing, or compliance assessments

**Recommended Next Steps:**
1. Review this report with your security team and subject matter experts
2. Validate findings against your actual system architecture and controls
3. Conduct additional manual threat modeling sessions
4. Perform security testing to confirm identified vulnerabilities
5. Engage certified security professionals for critical systems

By using this AI-generated report, you acknowledge that it serves as a starting point for threat modeling activities and requires human expertise for validation and implementation.

**CRITICAL FORMATTING REQUIREMENTS:**

1. **Table Usage:** All findings, recommendations, risk matrices MUST use markdown tables
2. **Color-Coded Risk Levels:** Always use **CRITICAL** (red), **HIGH** (orange), **MEDIUM** (yellow), **LOW** (green)
3. **Unique Identifiers:** Use F### for findings, R### for recommendations, T### for threats
4. **Professional Tone:** Executive summary suitable for C-level review
5. **Document References:** Every finding must reference the source document

Generate the complete, detailed, professionally formatted threat assessment report now."""

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=16000,
        messages=[{"role": "user", "content": prompt}]
    )

    report = message.content[0].text if message.content else "No content returned"

    # Save to database
    assessment = ThreatAssessment(
        organization_id=user.organization_id,
        user_id=user.id,
        project_name=project_info['name'],
        framework=framework,
        risk_type=', '.join(risk_areas[:3]),
        system_description=documents_content[:500],
        assessment_report=report,
        report_html=report,
        report_meta={"framework": framework, "risk_areas": risk_areas},
        uploaded_files=[f.name for f in st.session_state.get('current_uploaded_files', [])],
        status="completed"
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)
    return report, assessment


def render_login(db: Session):
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("# 🔒 AI Threat Modeling Tool")
        st.markdown("### Sign in to continue")
        
        email = st.text_input("Email", placeholder="admin@example.com")
        password = st.text_input("Password", type="password", placeholder="Your password")
        
        if st.button("Sign In", type="primary", use_container_width=True):
            if not email or not password:
                st.warning("Please enter both email and password")
                return
            user = PasswordAuth.authenticate(email=email, password=password, db=db)
            if user:
                st.session_state.user_id = user.id
                st.session_state.user = user
                st.success(f"Welcome back, {user.full_name or user.email}!")
                # Clear SecureAI key on login to avoid storing it
                st.session_state.api_key_input = ""
                try:
                    os.environ.pop("ANTHROPIC_API_KEY", None)
                except Exception:
                    pass
                st.rerun()
            else:
                st.error("Invalid credentials")
        
        st.caption("Default: admin@example.com / admin123")


def render_sidebar(user: User):
    with st.sidebar:
        st.markdown("## Account")
        st.success(f"{user.email}")
        if user.is_org_admin or user.role == "super_admin":
            st.info("Administrator access")
        
        st.markdown("---")
        
        # API Key Configuration
        st.markdown("## ⚙️ Configuration")
        
        # Get current API key from environment
        current_key = os.getenv("ANTHROPIC_API_KEY", "")
        is_placeholder = current_key.startswith("sk-ant-api03-CHANGE")
        
        if is_placeholder or not current_key:
            st.warning("⚠️ API Key not configured")
        else:
            st.success("✓ API Key configured")
        
        # API Key input
        if 'api_key_input' not in st.session_state:
            st.session_state.api_key_input = current_key if not is_placeholder else ""
        
        api_key = st.text_input(
            "SecureAI API Key",
            type="password",
            value=st.session_state.api_key_input,
            placeholder="sk-ant-api03-...",
            help="Enter your SecureAI API key to enable threat assessments"
        )
        
        if api_key and api_key != st.session_state.api_key_input:
            st.session_state.api_key_input = api_key
            # Update environment variable for current session
            os.environ["ANTHROPIC_API_KEY"] = api_key
            st.success("✓ API Key updated for this session")
            st.caption("Note: Restart app to persist changes to .env file")

        # Optional persistence to .env when explicitly requested
        save_toggle = st.checkbox(
            "Save key to .env for this device",
            value=False,
            help="Writes ANTHROPIC_API_KEY to the project's .env file"
        )
        if st.button("💾 Save Key", use_container_width=True):
            if not api_key:
                st.error("Please enter a key first")
            elif not save_toggle:
                st.warning("Enable 'Save key to .env' to confirm persistence")
            else:
                try:
                    from pathlib import Path
                    env_path = Path(__file__).parent / ".env"
                    content = ""
                    if env_path.exists():
                        content = env_path.read_text(encoding="utf-8")
                    lines = content.splitlines() if content else []
                    written = False
                    new_lines = []
                    for line in lines:
                        if line.strip().startswith("ANTHROPIC_API_KEY="):
                            new_lines.append(f"ANTHROPIC_API_KEY={api_key}")
                            written = True
                        else:
                            new_lines.append(line)
                    if not written:
                        new_lines.append(f"ANTHROPIC_API_KEY={api_key}")
                    env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
                    # Update current process env as well
                    os.environ["ANTHROPIC_API_KEY"] = api_key
                    st.success("Key saved to .env")
                except Exception as e:
                    st.error(f"Failed to save key: {e}")
        
        if st.button("Sign Out", use_container_width=True):
            # Clear SecureAI key on logout
            st.session_state.api_key_input = ""
            try:
                os.environ.pop("ANTHROPIC_API_KEY", None)
            except Exception:
                pass
            st.session_state.user_id = None
            st.session_state.user = None
            st.rerun()


def render_threat_assessment_form(db: Session, user: User):
    """Render the comprehensive threat assessment form"""
    # Quick actions
    qa_col1, qa_col2 = st.columns([3, 1])
    with qa_col2:
        if st.button("➕ New Assessment", key="new_assessment_top", use_container_width=True):
            st.session_state.assessment_complete = False
            st.session_state.threat_report = None
            st.session_state.current_project_name = None
            st.session_state.current_assessment_id = None
            st.session_state.current_uploaded_files = []
            # Reset framework and risk selections
            for k in list(st.session_state.keys()):
                if k.startswith("framework_") or k.startswith("risk_"):
                    st.session_state[k] = False
            st.rerun()

    # Header
    st.markdown("## 📊 Project Information")
    
    col1, col2 = st.columns(2)
    with col1:
        project_name = st.text_input("Project Name *", placeholder="e.g., Customer Portal Application")
        app_type = st.selectbox("Application Type *", 
            ["Web Application", "Mobile Application", "API/Microservice", 
             "Desktop Application", "Cloud Service", "IoT System", "AI/ML Platform"])
        deployment = st.selectbox("Deployment Model *",
            ["Cloud (AWS)", "Cloud (Azure)", "Cloud (GCP)", "Cloud (Multi-Cloud)",
             "On-Premises", "Hybrid", "Edge Computing"])
    
    with col2:
        criticality = st.selectbox("Business Criticality *", ["Critical", "High", "Medium", "Low"])
        compliance = st.multiselect("Compliance Requirements",
            ["PCI-DSS", "GDPR", "HIPAA", "SOX", "ISO 27001", "SOC 2", "NIST", "FedRAMP"])
        environment = st.selectbox("Environment", ["Production", "Staging", "Development", "UAT", "DR/Backup"])
    
    # Upload Documents
    st.markdown("## 📁 Upload Project Documents")
    st.markdown('<div class="upload-box"><h3>📤 Drop your files here</h3><p>Architecture diagrams, design docs, data flows, API specs</p></div>', unsafe_allow_html=True)
    
    uploaded_files = st.file_uploader(
        "Choose files",
        accept_multiple_files=True,
        type=['pdf', 'docx', 'txt', 'md', 'png', 'jpg', 'jpeg', 'yaml', 'json'],
        label_visibility="collapsed"
    )
    
    if uploaded_files:
        st.success(f"✓ {len(uploaded_files)} file(s) uploaded")
        st.session_state.current_uploaded_files = uploaded_files
    
    # Framework Selection
    st.markdown("## 🎯 Select Threat Modeling Framework")
    st.markdown('<p style="color: #666; margin-bottom: 1rem;">Choose the framework that best fits your threat modeling needs</p>', unsafe_allow_html=True)
    
    framework_cols = st.columns(2)
    selected_framework = None
    
    for idx, (framework, details) in enumerate(FRAMEWORKS.items()):
        col = framework_cols[idx % 2]
        with col:
            is_selected = st.checkbox(framework, key=f"framework_{framework}", help=details['description'])
            if is_selected:
                selected_framework = framework
                st.markdown(f"""
                <div class='framework-card selected'>
                    <h4>{framework}</h4>
                    <p><strong>Focus:</strong> {details['focus']}</p>
                    <p><strong>Best For:</strong> {details['best_for']}</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class='framework-card'>
                    <h4>{framework}</h4>
                    <p>{details['description'][:100]}...</p>
                </div>
                """, unsafe_allow_html=True)
    
    # Risk Focus Areas
    st.markdown("## 🎲 Select Risk Focus Areas")
    st.markdown('<p style="color: #666; margin-bottom: 1rem;">Choose specific risk areas for detailed analysis</p>', unsafe_allow_html=True)
    
    selected_risks = []
    risk_cols = st.columns(2)
    
    for idx, (risk_area, details) in enumerate(RISK_AREAS.items()):
        col = risk_cols[idx % 2]
        with col:
            is_selected = st.checkbox(risk_area, value=True, key=f"risk_{risk_area}")
            if is_selected:
                selected_risks.append(risk_area)
                with st.expander(f"📋 Threats in {risk_area}"):
                    for threat in details['threats']:
                        st.markdown(f"- {threat}")
    
    # Generate Assessment
    st.markdown("## 🚀 Generate Threat Assessment")
    
    can_generate = project_name and selected_framework and len(selected_risks) > 0 and uploaded_files
    
    if not can_generate:
        missing = []
        if not project_name: missing.append("✗ Project Name")
        if not selected_framework: missing.append("✗ Framework")
        if len(selected_risks) == 0: missing.append("✗ Risk Areas")
        if not uploaded_files: missing.append("✗ Documents")
        st.warning(f"Complete: {', '.join(missing)}")
    else:
        st.success("✓ All fields complete - Ready to generate!")
    
    if st.button("🎯 Generate Threat Assessment Report", disabled=not can_generate, use_container_width=True):
        with st.spinner("Generating comprehensive assessment with SecureAI..."):
            try:
                documents_content = ""
                for file in uploaded_files:
                    content = extract_text_from_file(file)
                    documents_content += f"\n\n### {file.name}\n{content}"
                
                project_info = {
                    'name': project_name,
                    'app_type': app_type,
                    'deployment': deployment,
                    'criticality': criticality,
                    'compliance': compliance or ['None'],
                    'environment': environment
                }
                
                report, assessment = generate_threat_assessment(
                    project_info, documents_content, selected_framework, selected_risks, user, db
                )
                
                st.session_state.threat_report = report
                st.session_state.current_project_name = project_name
                st.session_state.current_assessment_id = assessment.id
                st.session_state.assessment_complete = True
                st.balloons()
                st.success("✅ Comprehensive threat assessment generated!")
                st.rerun()
            except Exception as e:
                st.error(f"Error: {str(e)}")
    
    # Display Results
    if st.session_state.assessment_complete and st.session_state.threat_report:
        st.markdown("---")
        st.markdown("## 📋 Threat Assessment Report")
        
        project_name_display = st.session_state.get('current_project_name', 'Project')
        
        col1, col2, col3 = st.columns([1.5, 1.5, 1])
        with col1:
            # PDF Download
            filename, content, mime = create_pdf_download(
                st.session_state.threat_report,
                project_name_display
            )
            st.download_button(
                "📥 Download as PDF" if mime == "application/pdf" else "📥 Download Report",
                content,
                file_name=filename,
                mime=mime,
                use_container_width=True
            )
            if mime != "application/pdf":
                st.caption("⚠️ PDF generation requires weasyprint. Downloading as Markdown.")
        
        with col2:
            # Markdown Download
            md_filename = f"Threat_Assessment_{project_name_display.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.md"
            st.download_button(
                "📄 Download as Markdown",
                st.session_state.threat_report,
                file_name=md_filename,
                mime="text/markdown",
                use_container_width=True
            )
        
        with col3:
            if st.button("🔄 New Assessment", use_container_width=True):
                st.session_state.assessment_complete = False
                st.session_state.threat_report = None
                st.session_state.current_project_name = None
                st.session_state.current_assessment_id = None
                st.rerun()
        
        st.markdown("---")
        with st.expander("📖 Full Report Content", expanded=True):
            st.markdown(st.session_state.threat_report)


def render_past_assessments(db: Session, user: User):
    """Render past assessments with filters and enhanced presentation"""
    st.markdown("# 📚 Past Assessments")
    st.markdown("View and manage all your threat assessment reports")
    st.markdown("---")
    
    # Get all assessments for this user
    all_assessments = (
        db.query(ThreatAssessment)
        .filter(ThreatAssessment.user_id == user.id)
        .order_by(ThreatAssessment.created_at.desc())
        .all()
    )
    
    if not all_assessments:
        st.info("🔍 No past assessments yet. Create your first threat assessment in the 'Threat Modeling' tab!")
        return
    
    # Filters
    st.markdown("### 🔎 Filter Assessments")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        # Get unique frameworks
        frameworks = sorted(list(set([a.framework for a in all_assessments if a.framework])))
        framework_filter = st.selectbox("Filter by Framework", ["All"] + frameworks, key="framework_filter")
    
    with col2:
        # Get unique risk types
        risk_types = sorted(list(set([a.risk_type for a in all_assessments if a.risk_type])))
        risk_filter = st.selectbox("Filter by Risk Type", ["All"] + risk_types, key="risk_filter")
    
    with col3:
        # Status filter
        status_filter = st.selectbox("Filter by Status", ["All", "completed", "draft", "in_progress"], key="status_filter")
    
    with col4:
        # Date range
        date_filter = st.selectbox("Date Range", ["All Time", "Last 7 Days", "Last 30 Days", "Last 90 Days"], key="date_filter")
    
    # Apply filters
    filtered_assessments = all_assessments
    
    if framework_filter != "All":
        filtered_assessments = [a for a in filtered_assessments if a.framework == framework_filter]
    
    if risk_filter != "All":
        filtered_assessments = [a for a in filtered_assessments if a.risk_type == risk_filter]
    
    if status_filter != "All":
        filtered_assessments = [a for a in filtered_assessments if a.status == status_filter]
    
    if date_filter != "All Time":
        from datetime import timedelta
        now = datetime.utcnow()
        days_map = {"Last 7 Days": 7, "Last 30 Days": 30, "Last 90 Days": 90}
        cutoff = now - timedelta(days=days_map[date_filter])
        filtered_assessments = [a for a in filtered_assessments if a.created_at >= cutoff]
    
    # Display count
    st.markdown(f"**Showing {len(filtered_assessments)} of {len(all_assessments)} assessments**")
    st.markdown("---")
    
    if not filtered_assessments:
        st.info("No assessments match the selected filters.")
        return
    
    # Display assessments in cards
    for assessment in filtered_assessments:
        # Extract risk summary from report (look for CRITICAL/HIGH keywords)
        report_text = assessment.assessment_report or ""
        critical_count = report_text.upper().count("CRITICAL")
        high_count = report_text.upper().count("HIGH")
        medium_count = report_text.upper().count("MEDIUM")
        
        # Create assessment card
        with st.container():
            st.markdown(f"""
            <div style="background: white; padding: 1.5rem; border-radius: 12px; border: 2px solid #e2e8f0; margin-bottom: 1.5rem;">
                <h3 style="margin: 0 0 0.5rem 0; color: #1e293b;">🔍 {assessment.project_name}</h3>
                <p style="color: #64748b; margin: 0 0 0.5rem 0;">
                    <strong>Date:</strong> {assessment.created_at.strftime('%B %d, %Y at %H:%M')} | 
                    <strong>Framework:</strong> {assessment.framework} | 
                    <strong>Status:</strong> <span style="color: #22c55e; font-weight: 600;">{assessment.status.upper()}</span>
                </p>
                <div style="margin-top: 0.25rem;">
                    <span style="background:#fee2e2;color:#991b1b;padding:4px 10px;border-radius:999px;margin-right:8px;font-weight:600;">CRITICAL {critical_count}</span>
                    <span style="background:#ffedd5;color:#9a3412;padding:4px 10px;border-radius:999px;margin-right:8px;font-weight:600;">HIGH {high_count}</span>
                    <span style="background:#fef3c7;color:#92400e;padding:4px 10px;border-radius:999px;margin-right:8px;font-weight:600;">MEDIUM {medium_count}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # Risk Summary and Download section
            col_summary, col_download = st.columns([2, 1])
            
            with col_summary:
                st.markdown("#### 📊 Risk Summary")
                
                # Risk metrics in columns
                risk_col1, risk_col2, risk_col3 = st.columns(3)
                with risk_col1:
                    st.metric("🔴 Critical", critical_count, delta=None)
                with risk_col2:
                    st.metric("🟠 High", high_count, delta=None)
                with risk_col3:
                    st.metric("🟡 Medium", medium_count, delta=None)
                
                # Risk areas covered
                st.markdown(f"**Risk Areas:** {assessment.risk_type}")
            
            with col_download:
                st.markdown("#### 📥 Download")
                
                # PDF Download
                filename, content, mime = create_pdf_download(
                    assessment.assessment_report,
                    assessment.project_name
                )
                st.download_button(
                    "📄 Download PDF" if mime == "application/pdf" else "📄 Download Report",
                    content,
                    file_name=filename,
                    mime=mime,
                    key=f"pdf_{assessment.id}",
                    use_container_width=True
                )
                
                # Markdown Download
                st.download_button(
                    "📝 Download Markdown",
                    assessment.assessment_report,
                    file_name=f"{assessment.project_name}_assessment_{assessment.id}.md",
                    mime="text/markdown",
                    key=f"md_{assessment.id}",
                    use_container_width=True
                )
            
            # View full report in expander
            with st.expander("📖 View Full Report"):
                st.markdown(assessment.assessment_report)
            
            st.markdown("---")


def main():
    db = get_db_session()
    try:
        user = load_user(db)
        st.session_state.user = user

        if not user:
            render_login(db)
            return

        render_sidebar(user)
        
        # Hero section at the top
        st.markdown(
            """
            <div style='text-align: center; padding: 1rem 0 2rem 0;'>
                <h1>🔒 AI-Powered Threat Modeling Tool</h1>
                <p style='color: #64748b; font-size: 1.1rem;'>Enterprise-grade threat assessment powered by SecureAI</p>
            </div>
            """,
            unsafe_allow_html=True,
        )

        if user.is_org_admin or user.role == "super_admin":
            tab1, tab2, tab3 = st.tabs(["Threat Modeling", "Past Assessments", "Admin Dashboard"])
            with tab1:
                render_threat_assessment_form(db, user)
            with tab2:
                render_past_assessments(db, user)
            with tab3:
                admin_dashboard.render_admin_dashboard()
        else:
            tab1, tab2 = st.tabs(["Threat Modeling", "Past Assessments"])
            with tab1:
                render_threat_assessment_form(db, user)
            with tab2:
                render_past_assessments(db, user)
    finally:
        db.close()


if __name__ == "__main__":
    main()
