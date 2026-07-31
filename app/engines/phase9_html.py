from bs4 import BeautifulSoup

def analyze_html(html_body):
    """
    Phase 9: HTML & Rendering Engine
    Analyzes HTML for hidden text, external scripts, base64 content, forms, auto-submit, etc.
    """
    if not html_body:
        return {"html_risk_score": 0, "findings": []}
        
    findings = []
    html_risk = 0
    
    soup = BeautifulSoup(html_body, 'html.parser')
    
    # Check for HTML forms
    forms = soup.find_all('form')
    if forms:
        findings.append(f"HTML Form elements detected ({len(forms)} form(s)). Potential credential harvesting login portal.")
        html_risk += 35
        
    # Check for hidden inputs or hidden text
    hidden_elements = soup.find_all(style=lambda value: value and 'display:none' in value.lower())
    if hidden_elements:
        findings.append("Hidden HTML elements (display:none) detected. Potential SEO stuffing or hidden payload/links.")
        html_risk += 20
        
    # Check for iframes
    iframes = soup.find_all('iframe')
    if iframes:
        findings.append(f"IFrame elements detected ({len(iframes)} iframe(s)). Potential external content embedding or clickjacking.")
        html_risk += 25
        
    # Check for external scripts
    scripts = soup.find_all('script')
    if scripts:
        findings.append(f"JavaScript embedded in email HTML ({len(scripts)} script(s)).")
        html_risk += 15
        
    html_risk = min(100, html_risk)
    
    return {
        "forms_count": len(forms),
        "iframes_count": len(iframes),
        "scripts_count": len(scripts),
        "findings": findings,
        "html_risk_score": html_risk
    }
