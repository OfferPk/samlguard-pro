\# SAMLGuard Pro — Architectural Specification (v1.0.0)

\#\# 1\. Executive Technical Overview

\*\*SAMLGuard Pro\*\* is an enterprise SAML 2.0 Identity Provider (IdP) / Service Provider (SP) engineering studio, XML Signature (XMLDSig) verifier, XML Signature Wrapping (XSW 1–8) vulnerability auditor, and zero-trust SSO gateway synthesizer.

SAML 2.0 remains the ubiquitous standard for enterprise federated Single Sign-On (SSO) across enterprise identity providers (Okta, Microsoft Entra ID / Azure AD, PingIdentity, OneLogin, Google Workspace SAML) and B2B SaaS platforms.

However, because SAML 2.0 relies on complex XML structures and W3C XMLDSig, subtle discrepancies between how the signature verifier and the application business logic process XML trees lead to catastrophic security vulnerabilities.

\---

\#\# 2\. System Architecture & Subsystems

\`\`\`  
\+-----------------------------------------------------------------------------------+  
|                             SAMLGuard Pro Architecture                            |  
\+-----------------------------------------------------------------------------------+  
                                          |  
        \+---------------------------------+---------------------------------+  
        |                                 |                                 |  
        v                                 v                                 v  
\+-----------------------+     \+-----------------------+     \+-----------------------+  
|      saml-engine      |     |     saml-auditor      |     |    saml-simulator     |  
|  \- XML Metadata Parse |     |  \- 10-Point Scorecard |     |  \- XSW \#1 Attack      |  
|  \- XMLDSig Algorithms |     |  \- Grade A+ to F      |     |    DOM Mutation       |  
|  \- C14N Extractor     |     |  \- Remediation Engine |     |  \- Schema Hardening   |  
\+-----------------------+     \+-----------------------+     \+-----------------------+  
        |                                 |                                 |  
        \+---------------------------------+---------------------------------+  
                                          |  
                                          v  
\+-----------------------------------------------------------------------------------+  
|                        saml-synthesizer / CLI Generator                           |  
|  \- SP Metadata XML | Node.js Passport-SAML | Python OneLogin | Go Crewjam         |  
\+-----------------------------------------------------------------------------------+  
\`\`\`

\#\#\# 2.1 The XML Signature Wrapping (XSW) Threat Vector

XML Signature Wrapping exploits the separation between the XMLDSig signature validation and the application attribute extraction:  
1\. An attacker intercepts a legitimate, low-privilege signed SAMLResponse.  
2\. The attacker injects an unverified duplicate \`\<saml:Assertion\>\` containing \`admin@enterprise.com\` as the root child or wraps the genuine assertion in an \`\<Extensions\>\` container.  
3\. The XMLDSig engine validates the cryptographic signature over the original assertion ID (\`ID="\_real"\`).  
4\. The application logic executes a simple XPath query (e.g., \`//saml:Assertion/saml:Subject/saml:NameID\`) which returns the first assertion in the DOM (\`admin@enterprise.com\`).  
5\. \*\*How SAMLGuard Pro Defends\*\*:  
   \- Enforces strict schema validation ensuring exactly one \`\<saml:Assertion\>\` exists in the response.  
   \- Anchors signature reference URI directly to the assertion element consumed by the application.  
   \- Disables external entity resolution and DTD loading to completely neutralize XML External Entity (XXE) injection.

\---

\#\# 3\. Cryptographic Standards & Compatibility

| Standard | Scope | Requirement |  
|---|---|---|  
| \*\*OASIS SAML 2.0 Core\*\* | Protocol Specifications | Strict Assertion, Subject, Conditions, and AuthnStatement verification. |  
| \*\*OASIS SAML 2.0 Metadata\*\* | Federation Configuration | Valid \`EntityDescriptor\` with signing \`KeyDescriptor\` and ACS bindings. |  
| \*\*W3C XMLDSig & XML Encryption\*\* | Digital Signatures | Modern RSA-SHA256 / ECDSA-SHA256; strict deprecation of SHA-1. |  
| \*\*W3C Exclusive Canonicalization\*\* | C14N Algorithm | \`http\://www\.w3.org/2001/10/xml-exc-c14n\#\` to prevent namespace wrapping. |  
| \*\*NIST SP 800-63B\*\* | Federated Identity AAL2/3 | Strict audience restriction, recipient verification, and clock skew limits (\<= 300s). |

\---

\#\# 4\. 10-Point Zero-Trust SAML 2.0 Health Scorecard

1\. \*\*Dual Signature Verification (15 pts)\*\*: Ensures assertion and/or response envelope signatures are enforced.  
2\. \*\*Modern Signature Algorithm (15 pts)\*\*: Enforces RSA-SHA256 / SHA-512 and rejects insecure SHA-1.  
3\. \*\*XML Signature Wrapping (XSW 1–8) Defense (15 pts)\*\*: Schema-strict assertion cardinality and anchor binding.  
4\. \*\*XXE & External Entity Disablement (10 pts)\*\*: Disables external DTDs and entity expansion to prevent LFI and SSRF.  
5\. \*\*AudienceRestriction Gating (10 pts)\*\*: Confirms \`\<Audience\>\` matches SP Entity ID.  
6\. \*\*Recipient & ACS Destination Match (10 pts)\*\*: Validates \`Recipient\` against SP's HTTPS ACS endpoint.  
7\. \*\*Clock Skew & Temporal Validity Limits (10 pts)\*\*: Enforces \`\<Conditions\>\` bounded within 180–300s drift.  
8\. \*\*Assertion ID One-Time Nonce Replay Defense (5 pts)\*\*: Short-lived caching of processed assertion IDs.  
9\. \*\*Exclusive XML Canonicalization (C14N) (5 pts)\*\*: Validates \`xml-exc-c14n\#\` to prevent namespace injection.  
10\. \*\*SP-Initiated Flow & Request Signing (5 pts)\*\*: Signs outgoing \`AuthnRequest\` and enforces stateful RelayState tokens.  
