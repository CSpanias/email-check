#!/bin/bash

# =========================
# Email Report Generator (v1 - Simple, Stable)
#
# Author: Charalampos Spanias (mollysec)
# =========================

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 <email_check_log>"
    exit 1
fi

LOG_FILE="$1"

current_domain=""
SPF_LINE=""
DMARC_LINE=""

# -------------------------
# Generate report block
# -------------------------
generate_report() {

    DOMAIN="$1"
    SPF="$2"
    DMARC="$3"

    # SPF interpretation
    if [[ "$SPF" == *"~all"* ]]; then
        SPF_TEXT="utilises a softfail policy (~all), which does not enforce rejection of unauthorised senders"
    else
        SPF_TEXT="enforces a strict SPF policy (-all)"
    fi

    # DMARC interpretation
    if [[ "$DMARC" == *"p=reject"* ]]; then
        DMARC_TEXT="enforces a strict DMARC policy (p=reject, pct=100)"
    elif [[ "$DMARC" == *"p=quarantine"* ]]; then
        DMARC_TEXT="applies a quarantine DMARC policy (p=quarantine)"
    else
        DMARC_TEXT="does not enforce an effective DMARC policy"
    fi

cat <<EOF

## **$DOMAIN**

The domain was observed to implement a mature email security configuration, incorporating SPF, DKIM, DMARC, and MTA-STS controls.

SPF is configured to define authorised mail sources; however, it **$SPF_TEXT**. While this reduces the effectiveness of SPF as a standalone control, it is commonly supplemented by DMARC enforcement.

DKIM was confirmed to be correctly implemented and operational, ensuring that outbound email messages are cryptographically signed and can be validated by receiving systems.

The domain **$DMARC_TEXT**, providing an effective control for preventing spoofing and impersonation attacks.

MTA-STS is implemented in enforce mode, ensuring that email delivery is restricted to trusted mail servers over encrypted (TLS) connections.

Practical spoofing tests were performed, and unauthorised emails were not successfully delivered, confirming that authentication and enforcement mechanisms are functioning as intended.

**Overall, the domain demonstrates a strong email security posture**, with no evidence of exploitable spoofing vulnerabilities.

### **Recommendations**

- Enforce a strict SPF policy (-all) to explicitly reject unauthorised senders, rather than relying on softfail (~all).
- Maintain and regularly review authorised sending services defined in SPF records to minimise unnecessary exposure.
- Monitor DMARC reports to identify authentication failures, misconfigurations, or potential abuse.

### **References**

https://www.cyber.gc.ca/en/guidance/implementation-guidance-email-domain-protection

---

EOF
}

# -------------------------
# Parse log
# -------------------------
while read -r line; do

    # Detect domain safely
    if [[ "$line" =~ \[\*\]\ Domain:\ ([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}) ]]; then

        # Print previous domain before switching
        if [[ -n "$current_domain" ]]; then
            generate_report "$current_domain" "$SPF_LINE" "$DMARC_LINE"
        fi

        current_domain="${BASH_REMATCH[1]}"
        SPF_LINE=""
        DMARC_LINE=""

        continue
    fi

    # Only parse if inside a domain block
    [[ -z "$current_domain" ]] && continue

    # SPF
    if [[ "$line" =~ ^\"v=spf1 ]]; then
        SPF_LINE="$line"
    fi

    # DMARC
    if [[ "$line" =~ ^\"v=DMARC1 ]]; then
        DMARC_LINE="$line"
    fi

done < "$LOG_FILE"

# Last domain
if [[ -n "$current_domain" ]]; then
    generate_report "$current_domain" "$SPF_LINE" "$DMARC_LINE"
fi
