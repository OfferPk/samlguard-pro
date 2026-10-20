\# SAMLGuard Pro (v1.0.0)

\> \*\*Enterprise SAML 2.0 Identity Provider / Service Provider Metadata Studio, XML Signature & Key Wrapping Vulnerability Scanner & Zero-Trust SSO Gateway Synthesizer.\*\*

\[\!\[Compliance\](https\://img.shields.io/badge/Compliance-OASIS%20SAML%202.0%20%7C%20W3C%20XMLDSig-indigo)\](\#)  
\[\!\[Security Standard\](https\://img.shields.io/badge/Security-NIST%20SP%20800--63B%20Federated%20AAL2%2F3-blue)\](\#)  
\[\!\[Tests\](https\://img.shields.io/badge/Tests-7%2F7%20Passed-green)\](\#)  
\[\!\[License\](https\://img.shields.io/badge/License-Commercial%20%2F%20Developer-purple)\](\#)

\---

\#\# Overview

SAML 2.0 is the ubiquitous enterprise standard for Single Sign-On (SSO) across Okta, Microsoft Entra ID (Azure AD), PingIdentity, OneLogin, and Google Workspace.

However, implementing SAML 2.0 securely is notoriously difficult:  
\- \*\*XML Signature Wrapping (XSW 1–8)\*\*: Subtle discrepancies between XMLDSig cryptographic signature verification and application XPath attribute extraction allow attackers to inject spoofed admin assertions, achieving full authentication bypass without possessing the IdP private key.  
\- \*\*XML External Entity (XXE) Injection\*\*: Insecure XML parsers that resolve external DTDs lead to Local File Inclusion (LFI) and SSRF attacks.  
\- \*\*Insecure Ciphers\*\*: Legacy reliance on deprecated SHA-1 (\`rsa-sha1\`) rather than modern SHA-256 (\`rsa-sha256\`).  
\- \*\*SSO Broker Fees\*\*: Third-party brokers (WorkOS, BoxyHQ, Auth0 Enterprise) charge \$100–\$500/month in "Enterprise SSO Tax" per tenant.

\*\*SAMLGuard Pro\*\* provides a 100% client-side engineering studio and standalone Python CLI to inspect SAML XML metadata, audit configurations against a 10-point zero-trust scorecard (0–100%, Grades A+ to F), simulate XSW attacks versus schema-strict defenses, and synthesize production-ready verification backends for \*\*Node.js (@node-saml/passport-saml)\*\*, \*\*Python (python3-saml)\*\*, \*\*Go (crewjam/saml)\*\*, and standard \*\*SP XML Metadata (\`EntityDescriptor\`)\*\*.

\---

\#\# Key Features

1\. \*\*SAML 2.0 Metadata & Assertion Inspector\*\*:  
   \- Inspects SP and IdP XML metadata, Assertion Consumer Service (ACS) endpoints, and Single Sign-On (SSO) URLs.  
   \- Evaluates signature algorithms (RSA-SHA256, RSA-SHA512, ECDSA-SHA256, SHA-1).  
   \- Validates Exclusive Canonicalization (C14N) methods.  
   \- Decodes X.509 signing certificates and monitors expiration windows.  
2\. \*\*10-Point Zero-Trust SAML 2.0 Health Scorecard (0–100%, Grades A+ to F)\*\*:  
   \- Evaluates dual signature verification, modern cryptographic algorithms, XSW 1–8 defenses, XXE/DTD disablement, AudienceRestriction enforcement, Recipient/ACS destination matching, clock skew tolerances (\<= 300s), assertion ID replay protection, and SP-initiated AuthnRequest signing.  
3\. \*\*Interactive Visual Attack Simulator\*\*:  
   \- Demonstrates how XML Signature Wrapping (XSW \#1) tricks vulnerable parsers into granting admin access vs how SAMLGuard drops unverified wrapper nodes.  
4\. \*\*Multi-Backend & SP Metadata Synthesizer\*\*:  
   \- Generates production-ready snippets for \*\*SP Metadata XML\*\*, \*\*Node.js Express\*\*, \*\*Python FastAPI\*\*, and \*\*Go Gin\*\*.  
5\. \*\*Standalone Python CLI Tool (\`samlguard-cli.py\`)\*\*:  
   \- Zero external dependencies. Audits SAML policies and metadata, enforcing pre-commit CI/CD security gating.

\---

\#\# Directory Structure

\`\`\`  
samlguard-pro/  
├── source-code/  
│   ├── index.html                  \# Cyber dark UI web studio  
│   ├── samlguard.css               \# Responsive dark stylesheet  
│   ├── saml-engine.js              \# SAML XML metadata & XMLDSig inspector  
│   ├── saml-auditor.js             \# 10-point SAML 2.0 health auditor  
│   ├── saml-simulator.js           \# XSW \#1 exploit simulator  
│   ├── saml-synthesizer.js         \# Multi-backend IaC generator  
│   └── app.js                      \# UI state manager & event orchestrator  
├── build/  
│   ├── samlguard-pro-v1.0.0.zip    \# Distributable package  
│   └── samlguard-cli.py            \# Standalone Python CLI & CI/CD tool  
├── presets/  
│   ├── enterprise-okta-azure-sp.json  
│   ├── standard-b2b-saas-sso.json  
│   └── vulnerable-insecure-saml.json  
├── documentation/  
│   ├── ARCHITECTURE.md             \# Technical & threat modeling specification  
│   ├── USER\_GUIDE.md               \# User manual & CI/CD setup guide  
│   └── MONETIZATION\_AND\_MARKETING\_PLAYBOOK.md  
├── screenshots/  
│   ├── samlguard-studio-preview.svg  
│   └── saml-xsw-attack-architecture.svg  
└── tests/  
    └── test\_samlguard\_suite.py     \# Automated test suite (7/7 passed)  
\`\`\`

\---

\#\# Quickstart

\#\#\# Running the Web Studio  
Open \`source-code/index.html\` directly in any modern web browser. No build steps or node modules required.

\#\#\# Running the Automated Tests  
\`\`\`bash  
python3 tests/test\_samlguard\_suite.py  
\`\`\`

\#\#\# Running the Standalone CLI  
\`\`\`bash  
\# Audit an enterprise Okta/Azure preset  
python3 build/samlguard-cli.py audit \-p presets/enterprise-okta-azure-sp.json

\# Audit with strict CI/CD gating  
python3 build/samlguard-cli.py audit \-p presets/enterprise-okta-azure-sp.json \--strict  
\`\`\`  
