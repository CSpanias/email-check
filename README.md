# Email Check
A simple Bash script for performing email security configuration checks during external assessments.

## Features

- SPF record lookup and validation
- DMARC policy detection
- MTA-STS record and policy retrieval
- Basic alignment assessment (SPF + DMARC)
- Optional spoofing test using swaks
- Supports single domains or bulk input

## Usage

```bash
./email-dns-check.sh <domain>
./email-dns-check.sh <file_with_domains>
./email-dns-check.sh <domain> --spoof --to <email>

# Examples
./email-dns-check.sh example.com
./email-dns-check.sh domains.txt
./email-dns-check.sh example.com --spoof --to lab@domain.local
```

## Requirements

- dig
- curl
- swaks (for spoofing)
- postfix (local SMTP relay required for spoofing)


## Output

- Results are printed to the terminal
- A log file is also created (email_check_<timestamp>.log)


Notes

Alignment assessment is based on DNS configuration only
Full validation requires header analysis and spoofing testing
Spoofing must only be performed in authorised environments
