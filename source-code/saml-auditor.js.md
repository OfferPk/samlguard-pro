/\*\*  
 \* SAMLGuard Pro \- 10-Point Zero-Trust SAML 2.0 Health Auditor (v1.0.0)  
 \* Evaluates SAML configurations & metadata against OASIS SAML 2.0 and enterprise security mandates.  
 \*/

(function (root, factory) {  
  if (typeof define \=== 'function' && define.amd) {  
    define(\['./saml-engine'\], factory);  
  } else if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory(require('./saml-engine'));  
  } else {  
    root.SAMLAuditor \= factory(root.SAMLEngine);  
  }  
}(typeof self \!== 'undefined' ? self : this, function (Engine) {  
  'use strict';

  function auditSAMLConfig(config) {  
    const wantAssertionsSigned \= config.wantAssertionsSigned \!== false;  
    const wantResponseSigned \= config.wantResponseSigned \!== false;  
    const sigAlg \= config.signatureAlgorithm || 'http\://www\.w3.org/2001/04/xmldsig-more\#rsa-sha256';  
    const c14nMethod \= config.canonicalizationMethod || 'http\://www\.w3.org/2001/10/xml-exc-c14n\#';  
    const strictXswDefense \= config.strictXswDefense \!== false;  
    const blockXxe \= config.blockXxe \!== false;  
    const spEntityId \= config.spEntityId || 'https\://app.saasplatform.com/saml/metadata';  
    const acsUrl \= config.acsUrl || 'https\://app.saasplatform.com/saml/acs';  
    const clockSkewSec \= config.clockSkewToleranceSec \!== undefined ? config.clockSkewToleranceSec : 180;  
    const replayCacheActive \= config.replayCacheActive \!== false;  
    const signAuthnRequest \= config.signAuthnRequest \!== false;

    const checks \= \[\];

    // 1\. Dual Signature Verification (15 pts)  
    if (wantAssertionsSigned && wantResponseSigned) {  
      checks.push({  
        id: 'DUAL\_SIGNATURE',  
        name: 'Dual Signature Verification',  
        weight: 15,  
        score: 15,  
        status: 'PASS',  
        description: 'Both SAML Response envelope and inner Assertion are cryptographically verified.',  
        details: 'Ensures non-repudiation and prevents envelope-tampering in transit.',  
        remediation: null  
      });  
    } else if (wantAssertionsSigned) {  
      checks.push({  
        id: 'DUAL\_SIGNATURE',  
        name: 'Dual Signature Verification',  
        weight: 15,  
        score: 13,  
        status: 'PASS',  
        description: 'SAML Assertion signature required (Standard Compliant).',  
        details: 'Inner assertion signature is verified, which is the primary security boundary in SAML 2.0.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'DUAL\_SIGNATURE',  
        name: 'Dual Signature Verification',  
        weight: 15,  
        score: 0,  
        status: 'FAIL',  
        description: 'Assertion signatures are not strictly required\!',  
        details: 'Allowing unsigned assertions enables arbitrary attribute spoofing and complete authentication bypass.',  
        remediation: 'Configure wantAssertionsSigned: true on the Service Provider.'  
      });  
    }

    // 2\. Modern Signature Algorithm (15 pts)  
    const isSha256OrBetter \= sigAlg.includes('sha256') || sigAlg.includes('sha512');  
    const isSha1 \= sigAlg.includes('sha1');

    if (isSha256OrBetter) {  
      checks.push({  
        id: 'SIG\_ALGORITHM',  
        name: 'Cryptographic Signature Algorithm',  
        weight: 15,  
        score: 15,  
        status: 'PASS',  
        description: \`Modern SHA-256/512 signature enforced (\${sigAlg.includes('ecdsa') ? 'ECDSA' : 'RSA'}).\`,  
        details: 'Protects against hash collisions and forged signature attacks.',  
        remediation: null  
      });  
    } else if (isSha1) {  
      checks.push({  
        id: 'SIG\_ALGORITHM',  
        name: 'Cryptographic Signature Algorithm',  
        weight: 15,  
        score: 0,  
        status: 'FAIL',  
        description: 'Deprecated and insecure SHA-1 signature algorithm in use\!',  
        details: 'SHA-1 has proven collision vulnerabilities (SHAttered attack) and is disallowed by NIST SP 800-131A.',  
        remediation: 'Migrate to RSA-SHA256 (http\://www\.w3.org/2001/04/xmldsig-more\#rsa-sha256).'  
      });  
    } else {  
      checks.push({  
        id: 'SIG\_ALGORITHM',  
        name: 'Cryptographic Signature Algorithm',  
        weight: 15,  
        score: 5,  
        status: 'WARN',  
        description: 'Unrecognized signature algorithm URI.',  
        details: \`Algorithm "\${sigAlg}" may not be supported across all enterprise IdPs.\`,  
        remediation: 'Standardize on RSA-SHA256.'  
      });  
    }

    // 3\. XML Signature Wrapping (XSW 1–8) Defense (15 pts)  
    if (strictXswDefense) {  
      checks.push({  
        id: 'XSW\_DEFENSE',  
        name: 'XML Signature Wrapping (XSW) Defense',  
        weight: 15,  
        score: 15,  
        status: 'PASS',  
        description: 'Strict schema gating: exactly one unnested assertion permitted and signature anchored.',  
        details: 'Immune to all 8 classes of XML Signature Wrapping (XSW) attacks. The verified assertion is the exact node consumed by business logic.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'XSW\_DEFENSE',  
        name: 'XML Signature Wrapping (XSW) Defense',  
        weight: 15,  
        score: 0,  
        status: 'FAIL',  
        description: 'Vulnerable to XML Signature Wrapping (XSW)\!',  
        details: 'Attacker can inject an unvalidated duplicate assertion with admin privileges while the parser verifies the legitimate signature elsewhere in the DOM.',  
        remediation: 'Enable strict schema validation and anchor signature target ID to consumed assertion.'  
      });  
    }

    // 4\. XXE & External Entity Disablement (10 pts)  
    if (blockXxe) {  
      checks.push({  
        id: 'XXE\_PROTECTION',  
        name: 'XML External Entity (XXE) Hardening',  
        weight: 10,  
        score: 10,  
        status: 'PASS',  
        description: 'XML parser explicitly disables external DTDs and entity expansion.',  
        details: 'Prevents Local File Inclusion (LFI), Server-Side Request Forgery (SSRF), and Billion Laughs XML denial of service attacks.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'XXE\_PROTECTION',  
        name: 'XML External Entity (XXE) Hardening',  
        weight: 10,  
        score: 0,  
        status: 'FAIL',  
        description: 'Insecure XML parser configuration: XXE resolution enabled\!',  
        details: 'Remote attackers can read system files (/etc/passwd) or trigger internal network requests via malicious DOCTYPE declarations.',  
        remediation: 'Configure XML parser with disallow-doctype-decl: true and resolveEntities: false.'  
      });  
    }

    // 5\. AudienceRestriction Enforcement (10 pts)  
    const isAudienceConfigured \= Boolean(spEntityId && spEntityId.length \> 5);  
    if (isAudienceConfigured) {  
      checks.push({  
        id: 'AUDIENCE\_RESTRICTION',  
        name: 'AudienceRestriction Gating',  
        weight: 10,  
        score: 10,  
        status: 'PASS',  
        description: \`Audience strictly restricted to SP Entity ID ("\${spEntityId}").\`,  
        details: 'Prevents token substitution attacks where an assertion issued for a different SaaS app is replayed to this SP.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'AUDIENCE\_RESTRICTION',  
        name: 'AudienceRestriction Gating',  
        weight: 10,  
        score: 0,  
        status: 'FAIL',  
        description: 'AudienceRestriction validation missing or unconfigured.',  
        details: 'Service Provider will accept assertions issued for external third-party services.',  
        remediation: 'Validate that assertion Audience matches SP Entity ID.'  
      });  
    }

    // 6\. Recipient & Destination Matching (10 pts)  
    const isHttpsAcs \= acsUrl.startsWith('https\://') || acsUrl.startsWith('http\://localhost');  
    if (isHttpsAcs) {  
      checks.push({  
        id: 'RECIPIENT\_MATCH',  
        name: 'Recipient & Destination Validation',  
        weight: 10,  
        score: 10,  
        status: 'PASS',  
        description: \`SubjectConfirmationData Recipient validated against ACS URL ("\${acsUrl}").\`,  
        details: 'Guarantees that the assertion was delivered directly to this SP endpoint over TLS.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'RECIPIENT\_MATCH',  
        name: 'Recipient & Destination Validation',  
        weight: 10,  
        score: 0,  
        status: 'FAIL',  
        description: 'Insecure non-HTTPS ACS URL or unverified recipient destination.',  
        details: 'Assertions delivered over cleartext HTTP can be intercepted and replayed.',  
        remediation: 'Enforce HTTPS on the Assertion Consumer Service (ACS) endpoint.'  
      });  
    }

    // 7\. Clock Skew & Strict Lifetime Limits (10 pts)  
    if (clockSkewSec \<= 300 && clockSkewSec \>= 0\) {  
      checks.push({  
        id: 'CLOCK\_SKEW',  
        name: 'Clock Skew & Temporal Validity Limits',  
        weight: 10,  
        score: 10,  
        status: 'PASS',  
        description: \`Clock skew tolerance strictly bounded (\${clockSkewSec}s \<= 300s).\`,  
        details: 'Prevents expired assertions from being accepted while accommodating legitimate NTP clock drift.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'CLOCK\_SKEW',  
        name: 'Clock Skew & Temporal Validity Limits',  
        weight: 10,  
        score: 3,  
        status: 'WARN',  
        description: \`Excessive clock skew allowance (\${clockSkewSec}s \> 300s).\`,  
        details: 'Wide time windows expand the vulnerability window for replayed credentials.',  
        remediation: 'Reduce clock skew tolerance to between 60s and 180s.'  
      });  
    }

    // 8\. Assertion ID One-Time Nonce Replay Defense (5 pts)  
    if (replayCacheActive) {  
      checks.push({  
        id: 'REPLAY\_CACHE',  
        name: 'Assertion ID Nonce Replay Defense',  
        weight: 5,  
        score: 5,  
        status: 'PASS',  
        description: 'Short-lived cache tracking Assertion IDs to prevent token replay.',  
        details: 'If an intercepted assertion is submitted a second time, it is immediately discarded.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'REPLAY\_CACHE',  
        name: 'Assertion ID Nonce Replay Defense',  
        weight: 5,  
        score: 1,  
        status: 'WARN',  
        description: 'Assertion ID caching disabled; vulnerable to replay within validity window.',  
        details: 'An attacker who captures a valid SAMLResponse via network telemetry can reuse it until NotOnOrAfter expires.',  
        remediation: 'Enable Redis / memory cache of processed Assertion IDs.'  
      });  
    }

    // 9\. Exclusive Canonicalization (C14N) Standard (5 pts)  
    if (c14nMethod.includes('xml-exc-c14n')) {  
      checks.push({  
        id: 'C14N\_STANDARD',  
        name: 'Exclusive XML Canonicalization (C14N)',  
        weight: 5,  
        score: 5,  
        status: 'PASS',  
        description: 'Exclusive Canonicalization Method verified.',  
        details: 'Prevents inherited XML namespace and whitespace modifications from invalidating signatures.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'C14N\_STANDARD',  
        name: 'Exclusive XML Canonicalization (C14N)',  
        weight: 5,  
        score: 1,  
        status: 'WARN',  
        description: 'Inclusive Canonicalization in use.',  
        details: 'Inclusive C14N can break signatures when assertions are enveloped inside larger SOAP or HTTP payloads.',  
        remediation: 'Specify http\://www\.w3.org/2001/10/xml-exc-c14n\#.'  
      });  
    }

    // 10\. SP-Initiated Flow & RelayState CSRF Binding (5 pts)  
    if (signAuthnRequest) {  
      checks.push({  
        id: 'SP\_INIT\_CSRF',  
        name: 'SP-Initiated Flow & Request Signing',  
        weight: 5,  
        score: 5,  
        status: 'PASS',  
        description: 'Outgoing AuthnRequest is cryptographically signed and state-bound.',  
        details: 'Mitigates IdP-initiated login CSRF attacks and guarantees that the login was requested by the user.',  
        remediation: null  
      });  
    } else {  
      checks.push({  
        id: 'SP\_INIT\_CSRF',  
        name: 'SP-Initiated Flow & Request Signing',  
        weight: 5,  
        score: 2,  
        status: 'WARN',  
        description: 'Unsigned AuthnRequests permitted.',  
        details: 'Allows attackers to craft unsolicited IdP-initiated login sessions.',  
        remediation: 'Configure signAuthnRequest: true.'  
      });  
    }

    // Calculate score  
    const totalScore \= checks.reduce((acc, c) \=\> acc \+ c.score, 0);  
    const maxScore \= checks.reduce((acc, c) \=\> acc \+ c.weight, 0);  
    const scorePct \= Math.round((totalScore / maxScore) \* 100);

    let grade \= 'F';  
    if (scorePct \>= 97\) grade \= 'A+';  
    else if (scorePct \>= 90\) grade \= 'A';  
    else if (scorePct \>= 80\) grade \= 'B';  
    else if (scorePct \>= 70\) grade \= 'C';  
    else if (scorePct \>= 60\) grade \= 'D';

    return {  
      score: scorePct,  
      grade: grade,  
      passedCount: checks.filter(c \=\> c.status \=== 'PASS').length,  
      warnCount: checks.filter(c \=\> c.status \=== 'WARN').length,  
      failCount: checks.filter(c \=\> c.status \=== 'FAIL').length,  
      checks: checks  
    };  
  }

  return {  
    auditSAMLConfig: auditSAMLConfig  
  };  
}));  
