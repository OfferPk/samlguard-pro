/\*\*  
 \* SAMLGuard Pro \- SAML 2.0 Metadata & Assertion Engine (v1.0.0)  
 \* Standards compliant with OASIS SAML 2.0 Core & W3C XML Signature (XMLDSig).  
 \*/

(function (root, factory) {  
  if (typeof define \=== 'function' && define.amd) {  
    define(\[\], factory);  
  } else if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory();  
  } else {  
    root.SAMLEngine \= factory();  
  }  
}(typeof self \!== 'undefined' ? self : this, function () {  
  'use strict';

  const SIG\_ALGORITHMS \= {  
    'http\://www\.w3.org/2001/04/xmldsig-more\#rsa-sha256': { name: 'RSA-SHA256', secure: true, recommended: true },  
    'http\://www\.w3.org/2001/04/xmldsig-more\#rsa-sha512': { name: 'RSA-SHA512', secure: true, recommended: true },  
    'http\://www\.w3.org/2001/04/xmldsig-more\#ecdsa-sha256': { name: 'ECDSA-SHA256', secure: true, recommended: true },  
    'http\://www\.w3.org/2000/09/xmldsig\#rsa-sha1': { name: 'RSA-SHA1 (Insecure)', secure: false, recommended: false },  
    'http\://www\.w3.org/2000/09/xmldsig\#dsa-sha1': { name: 'DSA-SHA1 (Deprecated)', secure: false, recommended: false }  
  };

  const C14N\_ALGORITHMS \= {  
    'http\://www\.w3.org/2001/10/xml-exc-c14n\#': { name: 'Exclusive C14N (Without Comments)', secure: true },  
    'http\://www\.w3.org/2001/10/xml-exc-c14n\#WithComments': { name: 'Exclusive C14N (With Comments)', secure: true },  
    'http\://www\.w3.org/TR/2001/REC-xml-c14n-20010315': { name: 'Inclusive C14N (Legacy / Vulnerable)', secure: false }  
  };

  /\*\*  
   \* Parse XML Metadata or Configuration  
   \*/  
  function inspectSAMLConfig(config) {  
    if (\!config) {  
      return { valid: false, error: 'Empty configuration' };  
    }

    const spEntityId \= config.spEntityId || 'https\://app.saasplatform.com/saml/metadata';  
    const acsUrl \= config.acsUrl || 'https\://app.saasplatform.com/saml/acs';  
    const idpEntityId \= config.idpEntityId || 'https\://identity.enterprise.com/saml';  
    const ssoUrl \= config.ssoUrl || 'https\://identity.enterprise.com/saml/sso';  
    const sigAlgUri \= config.signatureAlgorithm || 'http\://www\.w3.org/2001/04/xmldsig-more\#rsa-sha256';  
    const c14nUri \= config.canonicalizationMethod || 'http\://www\.w3.org/2001/10/xml-exc-c14n\#';  
    const nameIdFormat \= config.nameIdFormat || 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';

    const sigInfo \= SIG\_ALGORITHMS\[sigAlgUri\] || { name: 'Custom / Unknown', secure: false, recommended: false };  
    const c14nInfo \= C14N\_ALGORITHMS\[c14nUri\] || { name: 'Custom C14N', secure: false };

    // Check HTTPS endpoints  
    const isHttpsAcs \= acsUrl.startsWith('https\://') || acsUrl.startsWith('http\://localhost');  
    const isHttpsSso \= ssoUrl.startsWith('https\://');

    return {  
      valid: true,  
      spEntityId: spEntityId,  
      acsUrl: acsUrl,  
      isHttpsAcs: isHttpsAcs,  
      idpEntityId: idpEntityId,  
      ssoUrl: ssoUrl,  
      isHttpsSso: isHttpsSso,  
      signatureAlgorithm: {  
        uri: sigAlgUri,  
        name: sigInfo.name,  
        secure: sigInfo.secure,  
        recommended: sigInfo.recommended  
      },  
      canonicalization: {  
        uri: c14nUri,  
        name: c14nInfo.name,  
        secure: c14nInfo.secure  
      },  
      nameIdFormat: nameIdFormat,  
      wantAssertionsSigned: config.wantAssertionsSigned \!== false,  
      wantResponseSigned: config.wantResponseSigned \!== false,  
      signAuthnRequest: config.signAuthnRequest \!== false,  
      blockXxe: config.blockXxe \!== false,  
      strictXswDefense: config.strictXswDefense \!== false,  
      clockSkewToleranceSec: config.clockSkewToleranceSec || 180,  
      certificate: {  
        issuer: config.certIssuer || 'CN=Enterprise IdP Signing Authority',  
        keySize: config.certKeySize || 2048,  
        daysRemaining: config.certDaysRemaining || 365,  
        isExpired: (config.certDaysRemaining || 365\) \<= 0  
      }  
    };  
  }

  /\*\*  
   \* Evaluate assertion conditions (NotBefore / NotOnOrAfter)  
   \*/  
  function evaluateConditions(notBeforeIso, notOnOrAfterIso, clockSkewSec, nowIso) {  
    const skew \= (clockSkewSec || 180\) \* 1000;  
    const now \= nowIso ? new Date(nowIso).getTime() : Date.now();  
    const nb \= notBeforeIso ? new Date(notBeforeIso).getTime() : 0;  
    const noa \= notOnOrAfterIso ? new Date(notOnOrAfterIso).getTime() : Infinity;

    const isTooEarly \= (now \+ skew) \< nb;  
    const isTooLate \= (now \- skew) \>= noa;  
    const isValid \= \!isTooEarly && \!isTooLate;

    return {  
      valid: isValid,  
      isTooEarly: isTooEarly,  
      isTooLate: isTooLate,  
      windowDurationSeconds: Math.round((noa \- nb) / 1000\)  
    };  
  }

  return {  
    SIG\_ALGORITHMS: SIG\_ALGORITHMS,  
    C14N\_ALGORITHMS: C14N\_ALGORITHMS,  
    inspectSAMLConfig: inspectSAMLConfig,  
    evaluateConditions: evaluateConditions  
  };  
}));  
