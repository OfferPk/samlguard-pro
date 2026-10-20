/\*\*  
 \* SAMLGuard Pro \- UI Controller & Orchestration (v1.0.0)  
 \*/

(function () {  
  'use strict';

  // DOM Elements  
  const presetSelect \= document.getElementById('presetSelect');  
  const loadPresetBtn \= document.getElementById('loadPresetBtn');  
  const spEntityIdInput \= document.getElementById('spEntityIdInput');  
  const acsUrlInput \= document.getElementById('acsUrlInput');  
  const sigAlgSelect \= document.getElementById('sigAlgSelect');  
  const c14nSelect \= document.getElementById('c14nSelect');  
  const checkWantAssertionsSigned \= document.getElementById('checkWantAssertionsSigned');  
  const checkStrictXsw \= document.getElementById('checkStrictXsw');  
  const checkBlockXxe \= document.getElementById('checkBlockXxe');  
  const checkReplayCache \= document.getElementById('checkReplayCache');  
  const certMetadataBox \= document.getElementById('certMetadataBox');

  // Scorecard Elements  
  const gradeBadge \= document.getElementById('gradeBadge');  
  const scoreValue \= document.getElementById('scoreValue');  
  const scoreGradeText \= document.getElementById('scoreGradeText');  
  const auditPassedBadge \= document.getElementById('auditPassedBadge');  
  const passCountEl \= document.getElementById('passCount');  
  const warnCountEl \= document.getElementById('warnCount');  
  const failCountEl \= document.getElementById('failCount');  
  const auditListEl \= document.getElementById('auditList');

  // Simulator Elements  
  const simXswBtn \= document.getElementById('simXswBtn');  
  const simEnterpriseBtn \= document.getElementById('simEnterpriseBtn');  
  const simTerminalLog \= document.getElementById('simTerminalLog');

  // Tab & Code Elements  
  const tabButtons \= document.querySelectorAll('.tab-btn');  
  const backendCodeOutput \= document.getElementById('backendCodeOutput');  
  const copyCodeBtn \= document.getElementById('copyCodeBtn');

  // Application State  
  let state \= {  
    spEntityId: 'https\://app.saasplatform.com/saml/metadata',  
    acsUrl: 'https\://app.saasplatform.com/saml/acs',  
    idpEntityId: 'https\://identity.enterprise.com/saml',  
    ssoUrl: 'https\://identity.enterprise.com/saml/sso',  
    signatureAlgorithm: 'http\://www\.w3.org/2001/04/xmldsig-more\#rsa-sha256',  
    canonicalizationMethod: 'http\://www\.w3.org/2001/10/xml-exc-c14n\#',  
    wantAssertionsSigned: true,  
    wantResponseSigned: true,  
    strictXswDefense: true,  
    blockXxe: true,  
    clockSkewToleranceSec: 180,  
    replayCacheActive: true,  
    signAuthnRequest: true,  
    certIssuer: 'CN=Enterprise Okta Signing Authority',  
    certKeySize: 2048,  
    certDaysRemaining: 365,  
    activeTab: 'metadata',  
    simScenario: 'enterprise'  
  };

  const PRESETS \= {  
    enterprise: {  
      spEntityId: 'https\://app.saasplatform.com/saml/metadata',  
      acsUrl: 'https\://app.saasplatform.com/saml/acs',  
      idpEntityId: 'https\://identity.enterprise.com/saml',  
      ssoUrl: 'https\://identity.enterprise.com/saml/sso',  
      signatureAlgorithm: 'http\://www\.w3.org/2001/04/xmldsig-more\#rsa-sha256',  
      canonicalizationMethod: 'http\://www\.w3.org/2001/10/xml-exc-c14n\#',  
      wantAssertionsSigned: true,  
      wantResponseSigned: true,  
      strictXswDefense: true,  
      blockXxe: true,  
      clockSkewToleranceSec: 180,  
      replayCacheActive: true,  
      signAuthnRequest: true,  
      certIssuer: 'CN=Enterprise Okta Signing Authority',  
      certKeySize: 2048,  
      certDaysRemaining: 365  
    },  
    standard: {  
      spEntityId: 'https\://dashboard.b2bapp.io/saml/metadata',  
      acsUrl: 'https\://dashboard.b2bapp.io/saml/acs',  
      idpEntityId: 'https\://login.partneridp.com/metadata',  
      ssoUrl: 'https\://login.partneridp.com/sso',  
      signatureAlgorithm: 'http\://www\.w3.org/2001/04/xmldsig-more\#rsa-sha256',  
      canonicalizationMethod: 'http\://www\.w3.org/2001/10/xml-exc-c14n\#',  
      wantAssertionsSigned: true,  
      wantResponseSigned: false,  
      strictXswDefense: true,  
      blockXxe: true,  
      clockSkewToleranceSec: 180,  
      replayCacheActive: true,  
      signAuthnRequest: true,  
      certIssuer: 'CN=Partner Identity Authority',  
      certKeySize: 2048,  
      certDaysRemaining: 240  
    },  
    vulnerable: {  
      spEntityId: 'http\://legacy.app.internal/saml',  
      acsUrl: 'http\://legacy.app.internal/saml/acs',  
      idpEntityId: 'http\://idp.internal/saml',  
      ssoUrl: 'http\://idp.internal/sso',  
      signatureAlgorithm: 'http\://www\.w3.org/2000/09/xmldsig\#rsa-sha1',  
      canonicalizationMethod: 'http\://www\.w3.org/TR/2001/REC-xml-c14n-20010315',  
      wantAssertionsSigned: false,  
      wantResponseSigned: false,  
      strictXswDefense: false,  
      blockXxe: false,  
      clockSkewToleranceSec: 3600,  
      replayCacheActive: false,  
      signAuthnRequest: false,  
      certIssuer: 'CN=Untrusted Self-Signed Authority',  
      certKeySize: 1024,  
      certDaysRemaining: \-15  
    }  
  };

  function init() {  
    bindEvents();  
    renderAll();  
  }

  function bindEvents() {  
    loadPresetBtn.addEventListener('click', () \=\> {  
      const p \= PRESETS\[presetSelect.value\];  
      if (p) {  
        state \= { ...state, ...p };  
        spEntityIdInput.value \= state.spEntityId;  
        acsUrlInput.value \= state.acsUrl;  
        sigAlgSelect.value \= state.signatureAlgorithm;  
        c14nSelect.value \= state.canonicalizationMethod;  
        checkWantAssertionsSigned.checked \= state.wantAssertionsSigned;  
        checkStrictXsw.checked \= state.strictXswDefense;  
        checkBlockXxe.checked \= state.blockXxe;  
        checkReplayCache.checked \= state.replayCacheActive;  
        renderAll();  
      }  
    });

    spEntityIdInput.addEventListener('input', (e) \=\> {  
      state.spEntityId \= e.target.value.trim() || 'https\://app.saasplatform.com/saml/metadata';  
      renderAll();  
    });

    acsUrlInput.addEventListener('input', (e) \=\> {  
      state.acsUrl \= e.target.value.trim() || 'https\://app.saasplatform.com/saml/acs';  
      renderAll();  
    });

    sigAlgSelect.addEventListener('change', (e) \=\> {  
      state.signatureAlgorithm \= e.target.value;  
      renderAll();  
    });

    c14nSelect.addEventListener('change', (e) \=\> {  
      state.canonicalizationMethod \= e.target.value;  
      renderAll();  
    });

    checkWantAssertionsSigned.addEventListener('change', (e) \=\> {  
      state.wantAssertionsSigned \= e.target.checked;  
      renderAll();  
    });

    checkStrictXsw.addEventListener('change', (e) \=\> {  
      state.strictXswDefense \= e.target.checked;  
      renderAll();  
    });

    checkBlockXxe.addEventListener('change', (e) \=\> {  
      state.blockXxe \= e.target.checked;  
      renderAll();  
    });

    checkReplayCache.addEventListener('change', (e) \=\> {  
      state.replayCacheActive \= e.target.checked;  
      renderAll();  
    });

    // Simulator Toggle  
    simXswBtn.addEventListener('click', () \=\> {  
      state.simScenario \= 'xsw\_vulnerable';  
      simXswBtn.classList.add('active');  
      simEnterpriseBtn.classList.remove('active');  
      renderSimulator();  
    });

    simEnterpriseBtn.addEventListener('click', () \=\> {  
      state.simScenario \= 'enterprise';  
      simEnterpriseBtn.classList.add('active');  
      simXswBtn.classList.remove('active');  
      renderSimulator();  
    });

    // Tabs  
    tabButtons.forEach(btn \=\> {  
      btn.addEventListener('click', () \=\> {  
        tabButtons.forEach(b \=\> b.classList.remove('active'));  
        btn.classList.add('active');  
        state.activeTab \= btn.getAttribute('data-tab');  
        renderBackendCode();  
      });  
    });

    // Copy Code  
    copyCodeBtn.addEventListener('click', () \=\> {  
      const text \= backendCodeOutput.textContent;  
      navigator.clipboard.writeText(text).then(() \=\> {  
        const orig \= copyCodeBtn.textContent;  
        copyCodeBtn.textContent \= 'Copied\!';  
        setTimeout(() \=\> copyCodeBtn.textContent \= orig, 1500);  
      });  
    });  
  }

  function renderAll() {  
    renderCertMetadata();  
    renderScorecard();  
    renderSimulator();  
    renderBackendCode();  
  }

  function renderCertMetadata() {  
    const inspected \= SAMLEngine.inspectSAMLConfig(state);  
    const cert \= inspected.certificate;

    certMetadataBox.innerHTML \= \`  
      \<div class="cert-field"\>\<span class="cert-label"\>IdP Issuer:\</span\>\<span class="cert-val"\>\${cert.issuer}\</span\>\</div\>  
      \<div class="cert-field"\>\<span class="cert-label"\>Public Key Size:\</span\>\<span class="cert-val"\>\${cert.keySize}-bit RSA\</span\>\</div\>  
      \<div class="cert-field"\>\<span class="cert-label"\>Signature Alg:\</span\>\<span class="cert-val" style="color: \${inspected.signatureAlgorithm.secure ? 'var(--accent-emerald)' : 'var(--accent-red)'}"\>\${inspected.signatureAlgorithm.name}\</span\>\</div\>  
      \<div class="cert-field"\>\<span class="cert-label"\>C14N Method:\</span\>\<span class="cert-val"\>\${inspected.canonicalization.name}\</span\>\</div\>  
      \<div class="cert-field"\>\<span class="cert-label"\>Validity Window:\</span\>\<span class="cert-val"\>\${cert.daysRemaining} days remaining (\${cert.isExpired ? '\<span style="color:var(--accent-red)"\>EXPIRED\</span\>' : '\<span style="color:var(--accent-emerald)"\>ACTIVE\</span\>'})\</span\>\</div\>  
      \<div class="cert-field"\>\<span class="cert-label"\>ACS Endpoint:\</span\>\<span class="cert-val" style="color: \${inspected.isHttpsAcs ? 'var(--accent-sky)' : 'var(--accent-red)'}"\>\${inspected.acsUrl} (\${inspected.isHttpsAcs ? 'TLS Verified' : 'Insecure Cleartext\!'})\</span\>\</div\>  
    \`;  
  }

  function renderScorecard() {  
    const audit \= SAMLAuditor.auditSAMLConfig(state);

    scoreValue.textContent \= \`\${audit.score} / 100\`;  
    gradeBadge.textContent \= audit.grade;  
    gradeBadge.className \= 'grade-badge';

    if (audit.grade \=== 'A+' || audit.grade \=== 'A') {  
      gradeBadge.classList.add('grade-a');  
      scoreGradeText.textContent \= 'Zero-Trust Hardened SSO';  
    } else if (audit.grade \=== 'B') {  
      gradeBadge.classList.add('grade-b');  
      scoreGradeText.textContent \= 'Good Architecture (Minor C14N / Replay Advisory)';  
    } else if (audit.grade \=== 'C' || audit.grade \=== 'D') {  
      gradeBadge.classList.add('grade-c');  
      scoreGradeText.textContent \= 'Suboptimal Security (Single Signature or Clock Drift)';  
    } else {  
      gradeBadge.classList.add('grade-f');  
      scoreGradeText.textContent \= 'Critical Flaw (XSW / XXE / Insecure SHA-1)';  
    }

    auditPassedBadge.textContent \= \`\${audit.passedCount} / \${audit.checks.length} Passed\`;  
    passCountEl.textContent \= audit.passedCount;  
    warnCountEl.textContent \= audit.warnCount;  
    failCountEl.textContent \= audit.failCount;

    // Render list  
    auditListEl.innerHTML \= audit.checks.map(check \=\> {  
      const statusClass \= check.status.toLowerCase();  
      const tagClass \= \`tag-\${statusClass}\`;  
      return \`  
        \<div class="audit-item \${statusClass}"\>  
          \<div class="audit-header-line"\>  
            \<span class="audit-title"\>\${check.name}\</span\>  
            \<span class="audit-tag \${tagClass}"\>\${check.status} (\${check.score}/\${check.weight} pts)\</span\>  
          \</div\>  
          \<div class="audit-desc"\>\${check.description} \${check.details}\</div\>  
          \${check.remediation ? \`\<div class="audit-remed"\>Remediation: \${check.remediation}\</div\>\` : ''}  
        \</div\>  
      \`;  
    }).join('');  
  }

  function renderSimulator() {  
    const sim \= SAMLSimulator.simulateAttack(state.simScenario, state);

    simTerminalLog.innerHTML \= sim.steps.map(s \=\> {  
      let extraHtml \= '';  
      if (s.observations) {  
        extraHtml \= \`\<ul style="margin-left: 20px; margin-top: 4px; color: \${sim.isVulnerable ? '\#fca5a5' : '\#86efac'};"\>  
          \${s.observations.map(obs \=\> \`\<li\>\${obs}\</li\>\`).join('')}  
        \</ul\>\`;  
      }  
      return \`  
        \<div class="log-line"\>  
          \<span class="log-step"\>\[Step \${s.step}\]\</span\>  
          \<span class="\${s.status \=== 'EXPLOITED' ? 'log-warn' : (s.status \=== 'SECURE' ? 'log-pass' : 'log-info')}"\>  
            \<strong\>\${s.title}:\</strong\> \${s.description}  
          \</span\>  
          \${extraHtml}  
        \</div\>  
      \`;  
    }).join('') \+ \`  
      \<div style="margin-top: 10px; padding-top: 8px; border-top: 1px dashed \#374151; font-weight: 700; color: \${sim.isVulnerable ? '\#ef4444' : '\#10b981'};"\>  
        Verdict: \${sim.summary}  
      \</div\>  
    \`;  
  }

  function renderBackendCode() {  
    const configs \= SAMLSynthesizer.synthesizeConfigurations(state);  
    backendCodeOutput.textContent \= configs\[state.activeTab\] || configs.metadata;  
  }

  if (document.readyState \=== 'loading') {  
    document.addEventListener('DOMContentLoaded', init);  
  } else {  
    init();  
  }  
})();  
