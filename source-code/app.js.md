/\*\*  
 \* CertGuard Pro \- UI Controller & Orchestration (v1.0.0)  
 \*/

(function () {  
  'use strict';

  // DOM Elements  
  const presetSelect \= document.getElementById('presetSelect');  
  const loadPresetBtn \= document.getElementById('loadPresetBtn');  
  const domainInput \= document.getElementById('domainInput');  
  const caGrid \= document.getElementById('caGrid');  
  const wildcardSegment \= document.getElementById('wildcardSegment');  
  const accountUriInput \= document.getElementById('accountUriInput');  
  const validationMethodSelect \= document.getElementById('validationMethodSelect');  
  const iodefInput \= document.getElementById('iodefInput');  
  const checkDnssec \= document.getElementById('checkDnssec');  
  const checkCritical \= document.getElementById('checkCritical');  
  const zonePreviewBox \= document.getElementById('zonePreviewBox');

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
  const simVulnerableBtn \= document.getElementById('simVulnerableBtn');  
  const simEnterpriseBtn \= document.getElementById('simEnterpriseBtn');  
  const simTerminalLog \= document.getElementById('simTerminalLog');

  // Tab & Code Elements  
  const tabButtons \= document.querySelectorAll('.tab-btn');  
  const dnsCodeOutput \= document.getElementById('dnsCodeOutput');  
  const copyCodeBtn \= document.getElementById('copyCodeBtn');

  // App State  
  let state \= {  
    domain: 'secure.globalbank.com',  
    authorizedCAs: \['digicert.com'\],  
    wildcardPolicy: 'block',  
    wildcardCAs: \[\],  
    accountUri: 'https\://acme.digicert.com/v2/acct/987654321',  
    validationMethod: 'dns-01',  
    iodefEmail: 'soc-alerts@globalbank.com',  
    iodefUrl: '',  
    isCritical: false,  
    hasDnssec: true,  
    activeTab: 'bind',  
    simScenario: 'enterprise'  
  };

  const PRESETS \= {  
    strict: {  
      domain: 'secure.globalbank.com',  
      authorizedCAs: \['digicert.com'\],  
      wildcardPolicy: 'block',  
      wildcardCAs: \[\],  
      accountUri: 'https\://acme.digicert.com/v2/acct/987654321',  
      validationMethod: 'dns-01',  
      iodefEmail: 'soc-alerts@globalbank.com',  
      iodefUrl: '',  
      isCritical: false,  
      hasDnssec: true  
    },  
    vulnerable: {  
      domain: 'unprotected-app.com',  
      authorizedCAs: \[\],  
      wildcardPolicy: 'inherit',  
      wildcardCAs: \[\],  
      accountUri: '',  
      validationMethod: 'any',  
      iodefEmail: '',  
      iodefUrl: '',  
      isCritical: false,  
      hasDnssec: false  
    },  
    cloud: {  
      domain: 'app.cloudsaas.io',  
      authorizedCAs: \['letsencrypt.org', 'pki.goog'\],  
      wildcardPolicy: 'separate',  
      wildcardCAs: \['letsencrypt.org'\],  
      accountUri: 'https\://acme-v02.api.letsencrypt.org/acme/acct/44556677',  
      validationMethod: 'dns-01',  
      iodefEmail: 'security@cloudsaas.io',  
      iodefUrl: '',  
      isCritical: false,  
      hasDnssec: true  
    }  
  };

  function init() {  
    renderCaChips();  
    bindEvents();  
    renderAll();  
  }

  function renderCaChips() {  
    caGrid.innerHTML \= CaaEngine.KNOWN\_CAS.map(ca \=\> {  
      const isChecked \= state.authorizedCAs.includes(ca.id);  
      return \`  
        \<label class="ca-chip \${isChecked ? 'active' : ''}" data-ca="\${ca.id}"\>  
          \<input type="checkbox" value="\${ca.id}" \${isChecked ? 'checked' : ''}\>  
          \<span\>\${ca.name}\</span\>  
        \</label\>  
      \`;  
    }).join('');  
  }

  function bindEvents() {  
    // Preset loader  
    loadPresetBtn.addEventListener('click', () \=\> {  
      const p \= PRESETS\[presetSelect.value\];  
      if (p) {  
        state \= { ...state, ...p };  
        domainInput.value \= state.domain;  
        accountUriInput.value \= state.accountUri;  
        validationMethodSelect.value \= state.validationMethod;  
        iodefInput.value \= state.iodefEmail || state.iodefUrl;  
        checkDnssec.checked \= state.hasDnssec;  
        checkCritical.checked \= state.isCritical;

        // Update wildcard buttons  
        wildcardSegment.querySelectorAll('.segment-btn').forEach(btn \=\> {  
          btn.classList.toggle('active', btn.getAttribute('data-policy') \=== state.wildcardPolicy);  
        });

        renderCaChips();  
        renderAll();  
      }  
    });

    // Domain Input  
    domainInput.addEventListener('input', (e) \=\> {  
      state.domain \= e.target.value.trim() || 'example.com';  
      renderAll();  
    });

    // CA Chip Clicks  
    caGrid.addEventListener('change', (e) \=\> {  
      const selected \= Array.from(caGrid.querySelectorAll('input\[type="checkbox"\]:checked')).map(cb \=\> cb.value);  
      state.authorizedCAs \= selected;  
      caGrid.querySelectorAll('.ca-chip').forEach(chip \=\> {  
        const caId \= chip.getAttribute('data-ca');  
        chip.classList.toggle('active', selected.includes(caId));  
      });  
      renderAll();  
    });

    // Wildcard Segment Buttons  
    wildcardSegment.addEventListener('click', (e) \=\> {  
      if (e.target.classList.contains('segment-btn')) {  
        wildcardSegment.querySelectorAll('.segment-btn').forEach(b \=\> b.classList.remove('active'));  
        e.target.classList.add('active');  
        state.wildcardPolicy \= e.target.getAttribute('data-policy');  
        renderAll();  
      }  
    });

    // Account URI  
    accountUriInput.addEventListener('input', (e) \=\> {  
      state.accountUri \= e.target.value.trim();  
      renderAll();  
    });

    // Validation Method  
    validationMethodSelect.addEventListener('change', (e) \=\> {  
      state.validationMethod \= e.target.value;  
      renderAll();  
    });

    // iodef Input  
    iodefInput.addEventListener('input', (e) \=\> {  
      const val \= e.target.value.trim();  
      if (val.startsWith('http\://') || val.startsWith('https\://')) {  
        state.iodefUrl \= val;  
        state.iodefEmail \= '';  
      } else {  
        state.iodefEmail \= val.replace(/^mailto:/, '');  
        state.iodefUrl \= '';  
      }  
      renderAll();  
    });

    // Flags  
    checkDnssec.addEventListener('change', (e) \=\> {  
      state.hasDnssec \= e.target.checked;  
      renderAll();  
    });

    checkCritical.addEventListener('change', (e) \=\> {  
      state.isCritical \= e.target.checked;  
      renderAll();  
    });

    // Simulator Toggle  
    simVulnerableBtn.addEventListener('click', () \=\> {  
      state.simScenario \= 'vulnerable';  
      simVulnerableBtn.classList.add('active');  
      simEnterpriseBtn.classList.remove('active');  
      renderSimulator();  
    });

    simEnterpriseBtn.addEventListener('click', () \=\> {  
      state.simScenario \= 'enterprise';  
      simEnterpriseBtn.classList.add('active');  
      simVulnerableBtn.classList.remove('active');  
      renderSimulator();  
    });

    // Tabs  
    tabButtons.forEach(btn \=\> {  
      btn.addEventListener('click', () \=\> {  
        tabButtons.forEach(b \=\> b.classList.remove('active'));  
        btn.classList.add('active');  
        state.activeTab \= btn.getAttribute('data-tab');  
        renderDnsOutput();  
      });  
    });

    // Copy Code Button  
    copyCodeBtn.addEventListener('click', () \=\> {  
      const text \= dnsCodeOutput.textContent;  
      navigator.clipboard.writeText(text).then(() \=\> {  
        const orig \= copyCodeBtn.textContent;  
        copyCodeBtn.textContent \= 'Copied\!';  
        setTimeout(() \=\> copyCodeBtn.textContent \= orig, 1500);  
      });  
    });  
  }

  function renderAll() {  
    renderZonePreview();  
    renderScorecard();  
    renderSimulator();  
    renderDnsOutput();  
  }

  function renderZonePreview() {  
    const records \= CaaEngine.buildRecords(state);  
    if (records.length \=== 0\) {  
      zonePreviewBox.textContent \= '; No CAA records configured (Domain is completely unprotected)';  
    } else {  
      zonePreviewBox.textContent \= CaaEngine.formatZoneFile(records, state.domain);  
    }  
  }

  function renderScorecard() {  
    const audit \= CaaAuditor.auditConfiguration(state);

    scoreValue.textContent \= \`\${audit.score} / 100\`;  
    gradeBadge.textContent \= audit.grade;  
    gradeBadge.className \= 'grade-badge';

    if (audit.grade \=== 'A+' || audit.grade \=== 'A') {  
      gradeBadge.classList.add('grade-a');  
      scoreGradeText.textContent \= 'Zero-Trust Enterprise Hardened';  
    } else if (audit.grade \=== 'B') {  
      gradeBadge.classList.add('grade-b');  
      scoreGradeText.textContent \= 'Good Coverage (Minor Wildcard / Account Exposure)';  
    } else if (audit.grade \=== 'C' || audit.grade \=== 'D') {  
      gradeBadge.classList.add('grade-c');  
      scoreGradeText.textContent \= 'Moderate Vulnerability (Broad CA Attack Surface)';  
    } else {  
      gradeBadge.classList.add('grade-f');  
      scoreGradeText.textContent \= 'Critical Vulnerability (Unprotected Domain)';  
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
    const sim \= CaaSimulator.simulateIssuance(state.simScenario, state);

    simTerminalLog.innerHTML \= sim.steps.map(s \=\> {  
      let extraHtml \= '';  
      if (s.dnsResponse) {  
        extraHtml \= \`\<div style="color: \#38bdf8; margin-top: 4px; font-family: monospace;"\>DNS Response: \${s.dnsResponse}\</div\>\`;  
      }  
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

  function renderDnsOutput() {  
    const configs \= DnsSynthesizer.synthesizeConfigurations(state);  
    dnsCodeOutput.textContent \= configs\[state.activeTab\] || configs.bind;  
  }

  if (document.readyState \=== 'loading') {  
    document.addEventListener('DOMContentLoaded', init);  
  } else {  
    init();  
  }  
})();  
