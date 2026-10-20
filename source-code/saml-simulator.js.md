/\*\*  
 \* SAMLGuard Pro \- Interactive XML Signature Wrapping (XSW) Simulator (v1.0.0)  
 \* Visualizes how XSW \#1 assertion injection bypasses vulnerable parsers vs Zero-Trust SAMLGuard defense.  
 \*/

(function (root, factory) {  
  if (typeof define \=== 'function' && define.amd) {  
    define(\[\], factory);  
  } else if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory();  
  } else {  
    root.SAMLSimulator \= factory();  
  }  
}(typeof self \!== 'undefined' ? self : this, function () {  
  'use strict';

  function simulateAttack(scenarioType, config) {  
    const isXswExploit \= scenarioType \=== 'xsw\_vulnerable';  
    const targetSp \= config.spEntityId || 'https\://app.saasplatform.com/saml/metadata';  
    const acsUrl \= config.acsUrl || 'https\://app.saasplatform.com/saml/acs';  
    const attackerIdentity \= 'attacker@evil-corp.com';  
    const spoofedAdmin \= 'admin@enterprise.com';

    if (isXswExploit) {  
      return {  
        scenario: 'XML Signature Wrapping (XSW \#1) Attack on Vulnerable Parser',  
        isVulnerable: true,  
        summary: 'CRITICAL AUTHENTICATION BYPASS: Attacker injected forged admin assertion; vulnerable parser validated legitimate signature elsewhere in DOM and granted root admin access.',  
        steps: \[  
          {  
            step: 1,  
            title: 'Interception of Legitimate Low-Privilege SAML Response',  
            status: 'INFO',  
            description: \`Attacker logs into IdP using disposable account "\${attackerIdentity}". Captures signed SAMLResponse destined for "\${acsUrl}".\`,  
            observations: \[  
              'Legitimate assertion contains: ID="\_real\_assertion\_123"',  
              \`Subject NameID: \${attackerIdentity}\`,  
              'Signature is valid and signed by authentic Enterprise IdP private key'  
            \]  
          },  
          {  
            step: 2,  
            title: 'DOM Mutation & Wrapper Element Injection (XSW \#1)',  
            status: 'EXPLOITED',  
            description: 'Attacker creates forged wrapper element in the XML payload and clones the assertion structure.',  
            observations: \[  
              \`Attacker crafts forged root assertion: ID="\_fake\_assertion\_999" with NameID: "\${spoofedAdmin}"\`,  
              'Original signed assertion is moved inside an \<Extensions\> wrapper or duplicate sibling node',  
              'The cryptographic signature still references ID="\_real\_assertion\_123"'  
            \]  
          },  
          {  
            step: 3,  
            title: 'Decoupled Signature Verification in Vulnerable Library',  
            status: 'EXPLOITED',  
            description: 'Vulnerable SAML parser evaluates XMLDSig by looking up ID="\_real\_assertion\_123".',  
            observations: \[  
              'XMLDSig Engine verifies signature over: ID="\_real\_assertion\_123" \-\> SIGNATURE VALID\!',  
              'Engine concludes: "The XML document has a valid signature."'  
            \]  
          },  
          {  
            step: 4,  
            title: 'Naïve XPath Attribute Extraction & Account Takeover',  
            status: 'EXPLOITED',  
            description: 'Application business logic queries first assertion: "/saml2p:Response/saml2:Assertion/saml2:Subject/saml2:NameID".',  
            observations: \[  
              \`XPath resolves to first assertion in DOM: "\${spoofedAdmin}"\!\`,  
              'Result: Attacker logged in as Enterprise Super Admin without possessing IdP private key\!'  
            \]  
          }  
        \]  
      };  
    }

    // Zero-Trust Hardened SAMLGuard Verification  
    return {  
      scenario: 'Zero-Trust Schema-Strict SAMLGuard Verification',  
      isVulnerable: false,  
      summary: 'SECURE DEFENSE: Strict schema enforcement detected multiple assertions and signature target mismatch. Exploit dropped with zero access.',  
      steps: \[  
        {  
          step: 1,  
          title: 'SAMLResponse Receipt & XML Parser Hardening',  
          status: 'INFO',  
          description: \`SAMLGuard intercepts incoming SAMLResponse at "\${acsUrl}". Parser runs with external DTDs and entities disabled (XXE blocked).\`,  
          observations: \[  
            'disallow-doctype-decl: true & resolveEntities: false',  
            'Pre-validation passes with zero entity expansion risk'  
          \]  
        },  
        {  
          step: 2,  
          title: 'Strict Schema & Assertion Cardinality Enforcement',  
          status: 'SECURE',  
          description: 'SAMLGuard performs schema validation before any signature checks, scanning for duplicate or nested assertion elements.',  
          observations: \[  
            'Detected multiple \<saml:Assertion\> tags (2 found, exactly 1 permitted)',  
            'Flagged suspicious unverified wrapper node: ID="\_fake\_assertion\_999"'  
          \]  
        },  
        {  
          step: 3,  
          title: 'Cryptographic Signature Anchor Binding',  
          status: 'SECURE',  
          description: 'SAMLGuard validates that the XML signature specifically covers the root assertion being extracted, not an unlinked detached element.',  
          observations: \[  
            'Signature Reference URI "\#\_real\_assertion\_123" does not match root element ID',  
            'Detected XML Signature Wrapping (XSW) payload mismatch'  
          \]  
        },  
        {  
          step: 4,  
          title: 'Assertion Rejection & Security Audit Alert',  
          status: 'SECURE',  
          description: 'Ceremony rejected immediately with HTTP 401 Unauthorized. Security incident telemetry recorded.',  
          observations: \[  
            'Forged admin assertion discarded',  
            \`Attacker "\${attackerIdentity}" blocked\`,  
            'Zero account takeover. 100% cryptographic integrity guaranteed.'  
          \]  
        }  
      \]  
    };  
  }

  return {  
    simulateAttack: simulateAttack  
  };  
}));  
