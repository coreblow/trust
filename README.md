# CoreBlow Trust

OWASP Agentic AI Policy Bundle and Security Verification Engine for CoreBlow.

## Overview

CoreBlow Trust is part of the CoreBlow public repository family. It provides machine-evaluable security policies, OWASP Top 10 for Agentic AI threat definitions, adversarial test fixtures, and a Node.js evaluation engine for CoreBlow Gateway security checks.

This repository follows the same ecosystem split that CoreBlow uses to keep release surfaces small, auditable, and independently governed.

## Repository Role

- Status: Active
- Phase: 6
- Priority: governance
- Kind: policy
- Family: CoreBlow public repository family
- Branding: CoreBlow

## Threat Models Covered (OWASP Top 10 Agentic AI)

- **ASI01: Prompt & Instruction Injection (`prompt-injection`)**: Direct or indirect adversarial prompt overrides.
- **ASI02: Command & Code Injection (`shell-injection`)**: Shell metacharacters, unauthorized file access, arbitrary child processes.
- **ASI03: Sensitive Information Disclosure (`secret-exfiltration`)**: Private keys, GitHub tokens, Slack tokens, credentials.
- **ASI04: Server-Side Request Forgery (`ssrf`)**: Probing cloud metadata (169.254.169.254) and unwhitelisted internal IPs.
- **ASI05: Privilege & Capability Escalation (`privilege-escalation`)**: Unauthorized administrative role manipulation.
- **ASI06: Unsafe Plugin Execution (`unsafe-plugin`)**: Undeclared permissions, core internals leakage.
- **ASI07: Supply Chain & Integrity Compromise (`supply-chain-tampering`)**: Unverified binaries and checksum bypasses.

## Usage

### Programmatic API

```js
import { evaluateAgenticPayload } from "@coreblow/trust";

const result = evaluateAgenticPayload("User prompt here");
if (!result.pass) {
  console.error("Security violation detected:", result.violations);
}
```

### Command Line Interface

```sh
node bin/trust-eval.mjs "ls -la; cat /etc/passwd"
node bin/trust-eval.mjs "safe prompt" --json
```

### Running Tests

```sh
npm test
```

## Release Policy

Do not publish packages, tags, installers, or release artifacts from this repository without explicit CoreBlow release approval.

Version changes must follow the coordinated CoreBlow release plan.

## Links

- [CoreBlow](https://github.com/coreblow/coreblow)
- [Documentation](https://docs.coreblow.com)
- [Website](https://coreblow.com)
- [Security Policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
