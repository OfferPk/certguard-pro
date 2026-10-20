\# CertGuard Pro — Comprehensive User Guide (v1.0.0)

\#\# Getting Started

CertGuard Pro can be run as an interactive client-side web application in your browser or used as an automated pre-commit CLI tool in CI/CD pipelines.

\---

\#\# 1\. Web Studio Quickstart

1\. Open \`source-code/index.html\` in any modern web browser.  
2\. Select an industry preset from the top dropdown (e.g. \*\*Strict Enterprise Banking & Healthcare\*\*) or enter your custom domain name.  
3\. Configure your Certificate Authority Authorization parameters:  
   \- \*\*Authorized CAs\*\*: Check Let's Encrypt, DigiCert, Google Trust Services, etc.  
   \- \*\*Wildcard Policy\*\*: Choose between "Prohibit Wildcards (;)", "Separate Wildcard CAs", or "Inherit Standard Policy".  
   \- \*\*ACME Account URI\*\*: Enter your ACME account ID URL to bind issuance to your infrastructure only.  
   \- \*\*Validation Method\*\*: Restrict to \`dns-01\` to defeat BGP routing hijacks.  
   \- \*\*Incident Alerting\*\*: Add an \`iodef\` email (e.g. \`security@yourdomain.com\`).  
4\. Inspect the \*\*10-Point Scorecard\*\*:  
   \- Verify that your domain achieves Grade A+ (100/100).  
   \- Review remediation notes for any warnings or failures.  
5\. Use the \*\*Interactive Attack Simulator\*\*:  
   \- Compare how an unprotected domain gets compromised versus how a CertGuard Pro hardened domain stops rogue CA issuance and dispatches an alert.  
6\. Export your DNS records:  
   \- Select your provider tab (\*\*BIND\*\*, \*\*Cloudflare\*\*, \*\*AWS Route53\*\*, \*\*Google Cloud\*\*, \*\*Azure\*\*, or \*\*Terraform\*\*) and click \*\*Copy Config\*\*.

\---

\#\# 2\. Using the Standalone Python CLI (\`certguard-cli.py\`)

The CLI runs on Python 3.6+ with zero external package dependencies.

\#\#\# Validating a CAA Record Syntax  
\`\`\`bash  
python3 build/certguard-cli.py validate '0 issue "letsencrypt.org; accounturi=https\://acme.org/123"'  
\# Output: \[VALID\] Tag: issue, Value: letsencrypt.org; accounturi=https\://acme.org/123, Flags: 0  
\`\`\`

\#\#\# Auditing a Preset or Zone File  
\`\`\`bash  
\# Audit a preset file  
python3 build/certguard-cli.py audit \-p presets/strict-enterprise-banking-caa.json

\# Audit with strict CI/CD gating (exits 1 if score \< 90 or failures \> 0\)  
python3 build/certguard-cli.py audit \-p presets/strict-enterprise-banking-caa.json \--strict

\# Output machine-readable JSON for dashboards  
python3 build/certguard-cli.py audit \-p presets/strict-enterprise-banking-caa.json \--json  
\`\`\`

\#\#\# Generating DNS Records  
\`\`\`bash  
python3 build/certguard-cli.py generate \--ca digicert.com \--domain mybank.com \--block-wildcards \--iodef soc@mybank.com  
\`\`\`

\---

\#\# 3\. GitHub Actions CI/CD Integration

Add this step to your deployment pipeline to verify that no infrastructure commit weakens your CAA policies:

\`\`\`yaml  
name: CAA & PKI Security CI  
on: \[push, pull\_request\]

jobs:  
  audit-caa:  
    runs-on: ubuntu-latest  
    steps:  
      \- uses: actions/checkout@v4  
      \- name: Set up Python  
        uses: actions/setup-python@v5  
        with:  
          python-version: '3.11'  
      \- name: Run CertGuard Pro Audit  
        run: |  
          python3 build/certguard-cli.py audit \\  
            \-p presets/strict-enterprise-banking-caa.json \\  
            \--strict  
\`\`\`  
