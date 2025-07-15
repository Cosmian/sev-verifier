# AMD SEV-SNP Verifier

## Overview

Basic CLI to verify an AMD SEV-SNP attestation from the following JSON schema:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "urn:microsoft:sev-attestation",
  "title": "SEV Attestation",
  "description": "AMD SEV-SNP attestation JSON schema",
  "type": "object",
  "properties": {
    "attestation": {
      "description": "Attestation report base64 encoded",
      "type": "string"
    },
    "platform_certificates": {
      "description": "Concatenation of VCEK, ASK, and ARK certificates in PEM format",
      "type": "string"
    },
    "uvm_endorsements": {
      "description": "UVM Endorsement (UVM reference info), base64 encoded COSE_Sign1 envelope",
      "type": "string"
    },
  },
  "required": [ "attestation", "platform_certificates", "uvm_endorsements" ]
}
```

## Install

```console
$ cargo install --path .
```

## Usage

```console
$ sev-verify --help
Usage: sev-verify --json-file <JSON_FILE> <--report-data <REPORT_DATA>|--b64-report-data <B64_REPORT_DATA>>

Options:
      --json-file <JSON_FILE>
      --report-data <REPORT_DATA>
      --b64-report-data <B64_REPORT_DATA>
  -h, --help                               Print help
  -V, --version                            Print version

```
