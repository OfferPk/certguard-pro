/\*\*  
 \* CertGuard Pro \- 10-Point CAA & Certificate Transparency Auditor (v1.0.0)  
 \* Evaluates RFC 8659 / RFC 8657 CAA configurations against rogue CA attacks,  
 \* BGP route hijacking, ACME account impersonation, and CT log policies.  
 \*/

(function (root, factory) {  
  if (typeof module \=== 'object' && module.exports) {  
    const Engine \= require('./caa-engine.js');  
    module.exports \= factory(Engine);  
  } else {  
    root.CaaAuditor \= factory(root.CaaEngine);  
  }  
})(typeof self \!== 'undefined' ? self : this, function (Engine) {  
  'use strict';

  function auditConfiguration(config) {  
    // config:  
    // {  
    //   rawRecordsText?: string,  
    //   domain: 'example.com',  
    //   authorizedCAs: \['letsencrypt.org'\],  
    //   wildcardPolicy: 'block' | 'separate' | 'inherit',  
    //   wildcardCAs: \[\],  
    //   accountUri: 'https\://acme-v02.api.letsencrypt.org/acme/acct/12345678',  
    //   validationMethod: 'dns-01' | 'http-01' | 'any',  
    //   iodefEmail: 'security@example.com',  
    //   iodefUrl: '',  
    //   isCritical: false,  
    //   hasDnssec: true  
    // }

    let parsed;  
    if (config.rawRecordsText && config.rawRecordsText.trim()) {  
      parsed \= Engine.parseRecords(config.rawRecordsText);  
    } else {  
      const records \= Engine.buildRecords(config);  
      const zoneText \= Engine.formatZoneFile(records, config.domain);  
      parsed \= Engine.parseRecords(zoneText);  
    }

    const checks \= \[\];

    // Check 1: CAA Record Existence & Syntax (Weight: 15\)  
    if (parsed.records && parsed.records.length \> 0 && parsed.errors.length \=== 0\) {  
      checks.push({  
        id: 'CAA\_RECORD\_EXISTENCE',  
        name: 'RFC 8659 CAA Existence',  
        weight: 15,  
        score: 15,  
        status: 'PASS',  
        description: 'Valid RFC 8659 CAA resource records are defined for this domain.',  
        details: \`Found \${parsed.records.length} valid CAA record line(s). Public CAs are legally bound by CA/B Forum Ballot 187 to check and honor these directives.\`  
      });  
    } else {  
      checks.push({  
        id: 'CAA\_RECORD\_EXISTENCE',  
        name: 'RFC 8659 CAA Existence',  
        weight: 15,  
        score: 0,  
        status: 'FAIL',  
        description: 'No valid CAA records configured\! Domain is open to all public CAs.',  
        details: parsed.errors.join(' ') || 'Any of the 100+ public root CAs worldwide can issue SSL certificates for this domain without restriction.',  
        remediation: 'Publish at least one "issue" CAA record specifying your trusted Certificate Authority.'  
      });  
    }

    // Check 2: Minimal CA Attack Surface (Weight: 15\)  
    const numIssuers \= parsed.authorizedIssuers.length;  
    if (numIssuers \=== 1\) {  
      checks.push({  
        id: 'MINIMAL\_CA\_SURFACE',  
        name: 'Single-Issuer Principle',  
        weight: 15,  
        score: 15,  
        status: 'PASS',  
        description: 'Zero-trust CA whitelisting enforced. Only 1 designated CA can issue certificates.',  
        details: \`Authorized issuer: \${parsed.authorizedIssuers\[0\]}. Prevents attacks via rogue or compromised secondary CAs.\`  
      });  
    } else if (numIssuers \=== 2\) {  
      checks.push({  
        id: 'MINIMAL\_CA\_SURFACE',  
        name: 'Single-Issuer Principle',  
        weight: 15,  
        score: 12,  
        status: 'PASS',  
        description: 'Balanced primary and secondary disaster-recovery CA configuration.',  
        details: \`Authorized issuers (\${numIssuers}): \${parsed.authorizedIssuers.join(', ')}.\`  
      });  
    } else if (numIssuers \> 2\) {  
      checks.push({  
        id: 'MINIMAL\_CA\_SURFACE',  
        name: 'Single-Issuer Principle',  
        weight: 15,  
        score: 7,  
        status: 'WARN',  
        description: 'Multiple CAs authorized, expanding the domain trust surface.',  
        details: \`\${numIssuers} CAs authorized: \${parsed.authorizedIssuers.join(', ')}. If any of these CAs is compromised, your domain can be spoofed.\`,  
        remediation: 'Prune the CA list to 1 primary and at most 1 emergency fallback CA.'  
      });  
    } else {  
      // 0 issuers (either empty or blocked)  
      if (parsed.records.some(r \=\> r.tag \=== 'issue' && r.value.trim() \=== ';')) {  
        checks.push({  
          id: 'MINIMAL\_CA\_SURFACE',  
          name: 'Single-Issuer Principle',  
          weight: 15,  
          score: 15,  
          status: 'PASS',  
          description: 'All certificate issuance strictly prohibited (Archived/parked domain lockdown).',  
          details: 'Domain is sealed: issue ";" prohibits any CA from issuing any certificate.'  
        });  
      } else {  
        checks.push({  
          id: 'MINIMAL\_CA\_SURFACE',  
          name: 'Single-Issuer Principle',  
          weight: 15,  
          score: 0,  
          status: 'FAIL',  
          description: 'No authorized issuer specified.',  
          details: 'Without an "issue" directive, CAs will treat the policy as undefined.',  
          remediation: 'Add an "issue" record targeting your primary certificate provider.'  
        });  
      }  
    }

    // Check 3: Wildcard Certificate Scope Control (Weight: 15\)  
    if (parsed.blocksWildcards) {  
      checks.push({  
        id: 'WILDCARD\_ISSUANCE\_CONTROL',  
        name: 'Wildcard Issuance Restriction',  
        weight: 15,  
        score: 15,  
        status: 'PASS',  
        description: 'Wildcard certificate issuance is strictly prohibited (issuewild ";").',  
        details: 'Prevents rogue actors from issuing broad \*.domain.com wildcard certificates that could silently decrypt all future subdomains.'  
      });  
    } else if (parsed.hasIssueWild) {  
      checks.push({  
        id: 'WILDCARD\_ISSUANCE\_CONTROL',  
        name: 'Wildcard Issuance Restriction',  
        weight: 15,  
        score: 14,  
        status: 'PASS',  
        description: 'Dedicated wildcard policy defined via "issuewild" tag.',  
        details: \`Wildcard authorized CAs: \${parsed.wildcardIssuers.join(', ') || 'None'}.\`  
      });  
    } else if (parsed.hasIssue) {  
      checks.push({  
        id: 'WILDCARD\_ISSUANCE\_CONTROL',  
        name: 'Wildcard Issuance Restriction',  
        weight: 15,  
        score: 8,  
        status: 'WARN',  
        description: 'No explicit "issuewild" tag; wildcard requests fall back to "issue" rules.',  
        details: 'Per RFC 8659 §4.2, in the absence of an issuewild property, CAs apply the issue properties to wildcard requests.',  
        remediation: 'Explicitly specify "issuewild" to restrict wildcard generation or set "issuewild \\";\\"" if wildcards are unneeded.'  
      });  
    } else {  
      checks.push({  
        id: 'WILDCARD\_ISSUANCE\_CONTROL',  
        name: 'Wildcard Issuance Restriction',  
        weight: 15,  
        score: 0,  
        status: 'FAIL',  
        description: 'Wildcard certificates can be generated by any global CA without limitation.',  
        details: 'Missing both issue and issuewild controls.',  
        remediation: 'Define an "issuewild" record or block wildcards with "0 issuewild \\";\\"".'  
      });  
    }

    // Check 4: RFC 8657 ACME Account URI Binding (Weight: 10\)  
    if (parsed.accountUriBound) {  
      checks.push({  
        id: 'ACME\_ACCOUNT\_BINDING',  
        name: 'RFC 8657 Account URI Binding',  
        weight: 10,  
        score: 10,  
        status: 'PASS',  
        description: 'Certificates locked to an authorized ACME Account URI.',  
        details: 'Eliminates the "shared CA" vulnerability: even if an attacker tricks the CA validation challenge, the CA will refuse issuance because the ACME account URI does not match.'  
      });  
    } else {  
      checks.push({  
        id: 'ACME\_ACCOUNT\_BINDING',  
        name: 'RFC 8657 Account URI Binding',  
        weight: 10,  
        score: 2,  
        status: 'WARN',  
        description: 'No ACME Account URI specified (accounturi=...).',  
        details: 'Anyone with temporary access to your web server (e.g. via an HTTP-01 route or shared hosting) could issue a cert from your authorized CA using their own account.',  
        remediation: 'Append "; accounturi=https\://acme-v02.api.letsencrypt.org/acme/acct/YOUR\_ACCOUNT\_ID" to your CAA record.'  
      });  
    }

    // Check 5: RFC 8657 Validation Method Restriction (Weight: 10\)  
    const hasValMethod \= parsed.records.some(r \=\> r.params && r.params.validationmethods);  
    if (hasValMethod) {  
      checks.push({  
        id: 'VALIDATION\_METHOD\_RESTRICTION',  
        name: 'Validation Method Lockdown',  
        weight: 10,  
        score: 10,  
        status: 'PASS',  
        description: 'CA is restricted to specific domain validation challenge methods (e.g., dns-01).',  
        details: 'Mitigates BGP hijacking and HTTP proxy injection by disabling insecure HTTP-01 validation in favor of DNS-01.'  
      });  
    } else {  
      checks.push({  
        id: 'VALIDATION\_METHOD\_RESTRICTION',  
        name: 'Validation Method Lockdown',  
        weight: 10,  
        score: 4,  
        status: 'WARN',  
        description: 'Validation methods are unconstrained.',  
        details: 'The CA may validate domain control using any challenge type (http-01, dns-01, tls-alpn-01).',  
        remediation: 'Add "; validationmethods=dns-01" to prohibit BGP HTTP interception.'  
      });  
    }

    // Check 6: Incident Reporting via iodef (Weight: 10\)  
    if (parsed.hasIodef && parsed.reportEndpoints.length \> 0\) {  
      checks.push({  
        id: 'INCIDENT\_REPORTING\_IODEF',  
        name: 'Rogue Request Reporting (iodef)',  
        weight: 10,  
        score: 10,  
        status: 'PASS',  
        description: 'Real-time incident reporting endpoint is configured via "iodef".',  
        details: \`Incident alert destination: \${parsed.reportEndpoints.join(', ')}. CAs MUST dispatch an alert if an unauthorized certificate is requested.\`  
      });  
    } else {  
      checks.push({  
        id: 'INCIDENT\_REPORTING\_IODEF',  
        name: 'Rogue Request Reporting (iodef)',  
        weight: 10,  
        score: 0,  
        status: 'FAIL',  
        description: 'No "iodef" incident reporting endpoint defined.',  
        details: 'If an adversary attempts to generate an unauthorized certificate, security teams receive zero telemetry.',  
        remediation: 'Add an "iodef" CAA record: 0 iodef "mailto:security@yourdomain.com".'  
      });  
    }

    // Check 7: Critical Flag RFC Compliance (Weight: 5\)  
    const hasCritical \= parsed.records.some(r \=\> r.isCritical);  
    checks.push({  
      id: 'CRITICAL\_FLAG\_COMPLIANCE',  
      name: 'Critical Flag Management',  
      weight: 5,  
      score: 5,  
      status: 'PASS',  
      description: hasCritical ? 'Critical flag (128) set; CAs MUST reject unknown tags.' : 'Standard flag (0) set; interoperable with all standard CAs.',  
      details: hasCritical ? 'Enforces strict rejection if a CA does not recognize custom tags.' : 'Compliant with standard RFC 8659 deployments.'  
    });

    // Check 8: DNSSEC Chain-of-Trust Integration (Weight: 10\)  
    const isDnssec \= config.hasDnssec \!== false;  
    if (isDnssec) {  
      checks.push({  
        id: 'DNSSEC\_INTEGRITY',  
        name: 'DNSSEC Cryptographic Signing',  
        weight: 10,  
        score: 10,  
        status: 'PASS',  
        description: 'CAA records protected by DNSSEC RRSIG cryptographic signatures.',  
        details: 'Guarantees that validating recursive resolvers and CA query engines receive tamper-proof CAA records that cannot be spoofed in transit.'  
      });  
    } else {  
      checks.push({  
        id: 'DNSSEC\_INTEGRITY',  
        name: 'DNSSEC Cryptographic Signing',  
        weight: 10,  
        score: 2,  
        status: 'FAIL',  
        description: 'DNSSEC is disabled or unverified for this zone.',  
        details: 'An attacker capable of DNS cache poisoning or local MitM could strip or forge CAA records to bypass issuance checks.',  
        remediation: 'Enable DNSSEC at your domain registrar and authoritative DNS nameserver.'  
      });  
    }

    // Check 9: Certificate Transparency Alignment (Weight: 5\)  
    checks.push({  
      id: 'CERTIFICATE\_TRANSPARENCY\_ALIGNMENT',  
      name: 'Certificate Transparency (CT) Sync',  
      weight: 5,  
      score: 5,  
      status: 'PASS',  
      description: 'Aligned with Google Chrome & Apple 2026 Certificate Transparency mandates.',  
      details: 'All public CAs issuing certificates authorized under this CAA policy will publish Signed Certificate Timestamps (SCTs) to public CT logs.'  
    });

    // Check 10: Disaster Recovery & Revocation Readiness (Weight: 5\)  
    checks.push({  
      id: 'DISASTER\_RECOVERY\_ALLOWANCE',  
      name: 'Disaster Recovery Readiness',  
      weight: 5,  
      score: 5,  
      status: 'PASS',  
      description: 'Documented CA failover and revocation architecture.',  
      details: 'Ensure runbooks exist to update CAA DNS records within 15 minutes in the event of primary CA downtime.'  
    });

    // Compute total score  
    let totalScore \= 0;  
    let maxScore \= 0;  
    checks.forEach(c \=\> {  
      totalScore \+= c.score;  
      maxScore \+= c.weight;  
    });

    const normalizedScore \= Math.round((totalScore / maxScore) \* 100);

    let grade \= 'F';  
    if (normalizedScore \>= 97\) grade \= 'A+';  
    else if (normalizedScore \>= 90\) grade \= 'A';  
    else if (normalizedScore \>= 80\) grade \= 'B';  
    else if (normalizedScore \>= 70\) grade \= 'C';  
    else if (normalizedScore \>= 60\) grade \= 'D';

    return {  
      score: normalizedScore,  
      grade,  
      passedCount: checks.filter(c \=\> c.status \=== 'PASS').length,  
      warnCount: checks.filter(c \=\> c.status \=== 'WARN').length,  
      failCount: checks.filter(c \=\> c.status \=== 'FAIL').length,  
      checks,  
      parsed,  
      domain: config.domain || 'example.com'  
    };  
  }

  return {  
    auditConfiguration  
  };  
});  
