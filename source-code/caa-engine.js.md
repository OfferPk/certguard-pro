/\*\*  
 \* CertGuard Pro \- RFC 8659 / RFC 8657 CAA Engine (v1.0.0)  
 \* IETF RFC 8659 (DNS Certification Authority Authorization)  
 \* IETF RFC 8657 (CAA Parameters for ACME & Account Binding)  
 \*/

(function (root, factory) {  
  if (typeof module \=== 'object' && module.exports) {  
    module.exports \= factory();  
  } else {  
    root.CaaEngine \= factory();  
  }  
})(typeof self \!== 'undefined' ? self : this, function () {  
  'use strict';

  const KNOWN\_CAS \= \[  
    { id: 'letsencrypt.org', name: "Let's Encrypt (ISRG)", acmeSupport: true },  
    { id: 'digicert.com', name: 'DigiCert', acmeSupport: true },  
    { id: 'sectigo.com', name: 'Sectigo', acmeSupport: true },  
    { id: 'pki.goog', name: 'Google Trust Services', acmeSupport: true },  
    { id: 'amazon.com', name: 'Amazon Trust Services (ACM)', acmeSupport: false },  
    { id: 'globalsign.com', name: 'GlobalSign', acmeSupport: true },  
    { id: 'entrust.net', name: 'Entrust', acmeSupport: false },  
    { id: 'ssl.com', name: 'SSL.com', acmeSupport: true }  
  \];

  const VALID\_TAGS \= \['issue', 'issuewild', 'iodef', 'contactemail', 'contactphone'\];  
  const VALID\_VALIDATION\_METHODS \= \['dns-01', 'http-01', 'tls-alpn-01'\];

  /\*\*  
   \* Parse raw CAA record lines (e.g. from BIND zone or dig output)  
   \*/  
  function parseRecords(rawText) {  
    const result \= {  
      raw: rawText || '',  
      records: \[\],  
      errors: \[\],  
      warnings: \[\],  
      hasIssue: false,  
      hasIssueWild: false,  
      hasIodef: false,  
      blocksWildcards: false,  
      accountUriBound: false,  
      authorizedIssuers: \[\],  
      wildcardIssuers: \[\],  
      reportEndpoints: \[\]  
    };

    if (\!rawText || typeof rawText \!== 'string' || \!rawText.trim()) {  
      result.warnings.push('No CAA records provided. By default, ANY public CA can issue certificates for this domain.');  
      return result;  
    }

    const lines \= rawText.split('\\n').map(l \=\> l.trim()).filter(l \=\> l && \!l.startsWith('\#') && \!l.startsWith(';'));

    for (let i \= 0; i \< lines.length; i++) {  
      const line \= lines\[i\];  
      // Format usually: \[domain\] \[TTL\] \[IN\] CAA \<flags\> \<tag\> "\<value\>"  
      // or simply: \<flags\> \<tag\> "\<value\>"  
      const match \= line.match(/(?:CAA\\s+)?(\\d+)\\s+(\[a-zA-Z0-9\]+)\\s+"(\[^"\]\*)"/i);  
      if (\!match) {  
        // Try unquoted fallback  
        const matchUnquoted \= line.match(/(?:CAA\\s+)?(\\d+)\\s+(\[a-zA-Z0-9\]+)\\s+(\[^;\\s\]+)/i);  
        if (\!matchUnquoted) {  
          result.errors.push(\`Line \${i \+ 1}: Malformed CAA record syntax: "\${line}". Format: \[flags\] \[tag\] "\[value\]"\`);  
          continue;  
        }  
      }

      const flags \= parseInt(match ? match\[1\] : 0, 10);  
      const tag \= (match ? match\[2\] : '').toLowerCase();  
      const value \= match ? match\[3\] : '';

      if (\!VALID\_TAGS.includes(tag)) {  
        result.warnings.push(\`Line \${i \+ 1}: Unrecognized property tag "\${tag}". (Flags: \${flags})\`);  
      }

      // Parse parameters (RFC 8657: e.g. "letsencrypt.org; accounturi=...; validationmethods=dns-01")  
      const parts \= value.split(';').map(p \=\> p.trim());  
      const caDomain \= parts\[0\] || '';  
      const params \= {};

      for (let p \= 1; p \< parts.length; p++) {  
        const paramPair \= parts\[p\];  
        const eqIdx \= paramPair.indexOf('=');  
        if (eqIdx \!== \-1) {  
          const pKey \= paramPair.substring(0, eqIdx).trim().toLowerCase();  
          const pVal \= paramPair.substring(eqIdx \+ 1).trim();  
          params\[pKey\] \= pVal;  
        }  
      }

      const parsedRec \= {  
        flags,  
        isCritical: (flags & 128\) \!== 0,  
        tag,  
        value,  
        caDomain,  
        params,  
        raw: line  
      };

      result.records.push(parsedRec);

      if (tag \=== 'issue') {  
        result.hasIssue \= true;  
        if (caDomain && caDomain \!== ';') {  
          result.authorizedIssuers.push(caDomain);  
        }  
        if (params.accounturi) {  
          result.accountUriBound \= true;  
        }  
      } else if (tag \=== 'issuewild') {  
        result.hasIssueWild \= true;  
        if (value.trim() \=== ';' || caDomain \=== ';') {  
          result.blocksWildcards \= true;  
        } else if (caDomain) {  
          result.wildcardIssuers.push(caDomain);  
        }  
        if (params.accounturi) {  
          result.accountUriBound \= true;  
        }  
      } else if (tag \=== 'iodef') {  
        result.hasIodef \= true;  
        result.reportEndpoints.push(value);  
      }  
    }

    return result;  
  }

  /\*\*  
   \* Build CAA records based on structured UI configuration  
   \*/  
  function buildRecords(config) {  
    const records \= \[\];  
    const domain \= (config.domain || 'example.com').trim().toLowerCase();  
    const flags \= config.isCritical ? 128 : 0;  
    const accountUri \= (config.accountUri || '').trim();  
    const validationMethod \= (config.validationMethod || '').trim();

    // Build parameter string for RFC 8657 (accounturi, validationmethods)  
    let paramSuffix \= '';  
    if (accountUri) {  
      paramSuffix \+= \`; accounturi=\${accountUri}\`;  
    }  
    if (validationMethod && validationMethod \!== 'any') {  
      paramSuffix \+= \`; validationmethods=\${validationMethod}\`;  
    }

    // 1\. Issue directives  
    const authorizedCAs \= Array.isArray(config.authorizedCAs) ? config.authorizedCAs : \['letsencrypt.org'\];  
    if (config.allowNoSingleCerts) {  
      records.push({  
        domain,  
        flags,  
        tag: 'issue',  
        value: ';',  
        comment: 'Strictly prohibit all single-name/SAN certificates'  
      });  
    } else {  
      for (const ca of authorizedCAs) {  
        records.push({  
          domain,  
          flags,  
          tag: 'issue',  
          value: \`\${ca}\${paramSuffix}\`,  
          comment: \`Authorize \${ca} for single & SAN certificates\`  
        });  
      }  
    }

    // 2\. Wildcard directives  
    if (config.wildcardPolicy \=== 'block') {  
      records.push({  
        domain,  
        flags,  
        tag: 'issuewild',  
        value: ';',  
        comment: 'Strictly prohibit wildcard (\*.domain) certificate issuance by any CA'  
      });  
    } else if (config.wildcardPolicy \=== 'separate') {  
      const wildcardCAs \= Array.isArray(config.wildcardCAs) && config.wildcardCAs.length \> 0 ? config.wildcardCAs : authorizedCAs;  
      for (const ca of wildcardCAs) {  
        records.push({  
          domain,  
          flags,  
          tag: 'issuewild',  
          value: \`\${ca}\${paramSuffix}\`,  
          comment: \`Authorize \${ca} specifically for wildcard certificates\`  
        });  
      }  
    }  
    // If 'inherit', issuewild is omitted, meaning CAs apply 'issue' rules to wildcard requests per RFC 8659 §4.2

    // 3\. Incident Reporting (iodef)  
    if (config.iodefEmail) {  
      records.push({  
        domain,  
        flags: 0,  
        tag: 'iodef',  
        value: \`mailto:\${config.iodefEmail.trim()}\`,  
        comment: 'Send incident reports on unauthorized certificate requests'  
      });  
    } else if (config.iodefUrl) {  
      records.push({  
        domain,  
        flags: 0,  
        tag: 'iodef',  
        value: config.iodefUrl.trim(),  
        comment: 'HTTP webhook for CAA violation reports'  
      });  
    }

    return records;  
  }

  /\*\*  
   \* Format records into standard DNS zone line format  
   \*/  
  function formatZoneFile(records, domain) {  
    const d \= domain || '@';  
    return records.map(r \=\> \`\${d} IN CAA \${r.flags} \${r.tag} "\${r.value}"\`).join('\\n');  
  }

  return {  
    KNOWN\_CAS,  
    VALID\_TAGS,  
    VALID\_VALIDATION\_METHODS,  
    parseRecords,  
    buildRecords,  
    formatZoneFile  
  };  
});  
