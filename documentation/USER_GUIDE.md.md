\# SAMLGuard Pro — Comprehensive User Guide (v1.0.0)

\#\# Getting Started

SAMLGuard Pro operates as an interactive in-browser development studio and as a standalone pre-commit Python CLI tool in CI/CD pipelines.

\---

\#\# 1\. Web Studio Quickstart

1\. Open \`source-code/index.html\` in any modern web browser.  
2\. Select an industry preset from the top dropdown:  
   \- \*\*Enterprise Okta & Azure AD FAPI-Compliant SP\*\* (Grade A+ 100/100)  
   \- \*\*Standard B2B SaaS Single Sign-On SP\*\* (Grade A+ 98/100)  
   \- \*\*Vulnerable Insecure SAML SP (SHA-1 & XSW Bypass)\*\* (Grade F 18/100)  
3\. Customize your Service Provider & Identity Provider parameters:  
   \- Service Provider (SP) Entity ID  
   \- Assertion Consumer Service (ACS) URL  
   \- Signature Algorithm (RSA-SHA256, RSA-SHA512, ECDSA-SHA256)  
   \- Canonicalization Method (Exclusive C14N vs Inclusive)  
   \- Toggle checkboxes: Want Assertions Signed, Strict XSW Defense, Block XXE / DTD, Replay Nonce Cache  
4\. Review the \*\*10-Point Scorecard\*\*:  
   \- Verify that your SP policy achieves Grade A+ (100/100).  
   \- Review remediation notes for any warnings or critical flaws.  
5\. Use the \*\*Interactive Attack Simulator\*\*:  
   \- Compare how an unvalidated XML parser falls victim to XSW \#1 signature wrapping vs how SAMLGuard drops unverified wrapper nodes.  
6\. Export your Implementation Code:  
   \- Choose between \*\*SP Metadata XML (\`EntityDescriptor\`)\*\*, \*\*Node.js Express (@node-saml/passport-saml)\*\*, \*\*Python FastAPI (python3-saml)\*\*, or \*\*Go Gin (crewjam/saml)\*\*.  
   \- Click \*\*Copy Implementation\*\* to paste directly into your project.

\---

\#\# 2\. Using the Standalone Python CLI (\`samlguard-cli.py\`)

The CLI runs on Python 3.6+ with zero external package dependencies.

\#\#\# Auditing a SAML Configuration Preset  
\`\`\`bash  
python3 build/samlguard-cli.py audit \-p presets/enterprise-okta-azure-sp.json  
\`\`\`

\#\#\# Auditing with Strict CI/CD Gating  
\`\`\`bash  
python3 build/samlguard-cli.py audit \-p presets/enterprise-okta-azure-sp.json \--strict  
\# Exits with 0 on pass, or 1 if score \< 90 or failures exist  
\`\`\`

\#\#\# Inspecting XML Metadata Files  
\`\`\`bash  
python3 build/samlguard-cli.py inspect /path/to/sp-metadata.xml  
\`\`\`

\#\#\# Generating Backend Boilerplate  
\`\`\`bash  
python3 build/samlguard-cli.py generate \--backend node \--sp-entity-id https\://myapp.com/saml/metadata  
\`\`\`

\---

\#\# 3\. GitHub Actions CI/CD Integration

Prevent insecure SAML configurations (e.g., enabling SHA-1 or disabling XSW checks) from being merged into production:

\`\`\`yaml  
name: SAML SSO Security CI  
on: \[push, pull\_request\]

jobs:  
  audit-saml:  
    runs-on: ubuntu-latest  
    steps:  
      \- uses: actions/checkout@v4  
      \- name: Set up Python  
        uses: actions/setup-python@v5  
        with:  
          python-version: '3.11'  
      \- name: Run SAMLGuard Pro Audit  
        run: |  
          python3 build/samlguard-cli.py audit \\  
            \-p presets/enterprise-okta-azure-sp.json \\  
            \--strict  
\`\`\`  
