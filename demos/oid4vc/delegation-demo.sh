#!/usr/bin/env bash
#
# Delegated SD-JWT (dSD-JWT) demo orchestration script.
#
# Flow: Issuer (Bank) -> Holder (End-User) -> Delegate Holder (Agent) -> Verifier (Merchant).
#
# This script launches the three services (Bank issuer, Merchant verifier, Agent)
# and starts a checkout, then prints a runbook for the human (End-User) to drive the Holder CLI
# for the single consent/paste step. The Holder is interactive and is NOT started by this script.

set -euo pipefail

OUTPUT_DIR=./output
mkdir -p "$OUTPUT_DIR"

ISSUER_URL=http://localhost:8088
MERCHANT_URL=http://localhost:8098
AGENT_URL=http://localhost:8108

cleanup() {
  for name in issuer agent verifier; do
    pid_var="${name}_pid"
    pid="${!pid_var:-}"
    if [ -n "$pid" ]; then
      kill "$pid" 2>/dev/null || true
      echo "Terminated $name (PID: $pid)"
      echo ; echo "=== $name logs ===" ; echo
      cat "$OUTPUT_DIR/$name.log"
    fi
  done
}
trap cleanup EXIT

wait_for() {
  local url=$1 name=$2
  echo -n "Waiting for $name ($url) "
  for _ in $(seq 1 120); do
    if curl -fsS -o /dev/null "$url" 2>/dev/null; then
      echo "- ready"
      return 0
    fi
    echo -n "."
    sleep 1
  done
  echo "- TIMEOUT"
  return 1
}

export RUST_LOG=${RUST_LOG:-info}

echo "Starting Bank issuer..."
cargo run --manifest-path ./issuer/Cargo.toml -F ci_demo > "$OUTPUT_DIR/issuer.log" 2>&1 &
issuer_pid=$!

echo "Starting Merchant verifier (-F delegate-sd-jwt)..."
cargo run --manifest-path ./verifier/Cargo.toml -F delegate-sd-jwt > "$OUTPUT_DIR/verifier.log" 2>&1 &
verifier_pid=$!

echo "Starting Agent (Delegate Holder)..."
cargo run --manifest-path ./agent/Cargo.toml > "$OUTPUT_DIR/agent.log" 2>&1 &
agent_pid=$!

wait_for "$ISSUER_URL/.well-known/openid-credential-issuer" "Bank issuer"
wait_for "$MERCHANT_URL/request_uri" "Merchant verifier"
wait_for "$AGENT_URL/request_uri" "Agent"

echo
echo "=== Starting checkout ==="

# The Merchant mints a fresh purchase_id at AR1 creation;
# the Agent extracts it and injects it into the delegation request (AR2).
MERCHANT_AR=$(curl -fsS "$MERCHANT_URL/request_uri")
AR2_INSTRUCTIONS=$(curl -fsS -XPOST "$AGENT_URL/checkout" \
  --data-urlencode "merchant_request_uri=$MERCHANT_AR")

# Pre-authorized credential offer for the Holder. In ci_demo mode the issuer has no
# Keycloak and does NOT support the authorization-code flow (PAR), so the Holder must
# use the pre-authorized code flow by resolving this offer.
CRED_OFFER=$(curl -fsS "$ISSUER_URL/create_credential_offer_uri_pre_auth_code_grant")

cat <<EOF

============================================================================
 Delegated SD-JWT demo — runbook
============================================================================
Services are up:
  Bank issuer    : $ISSUER_URL     (logs: $OUTPUT_DIR/issuer.log)
  Merchant       : $MERCHANT_URL   (logs: $OUTPUT_DIR/verifier.log)
  Agent          : $AGENT_URL      (logs: $OUTPUT_DIR/agent.log)

In a SEPARATE terminal (from demos/oid4vc/), run the Holder:

  cargo run --manifest-path ./holder/Cargo.toml -F delegate-sd-jwt

Then in the Holder prompts:
  1. Init mode                   : enter  2  (resolve a credential offer — ci_demo has no PAR).

  2. Voucher credential offer    : paste the pre-authorized offer below:
     $CRED_OFFER

  3. Transaction code            : enter  n  (the demo uses a dummy code).
     The Holder completes issuance and also obtains the voucher.

  4. Presentation flow           : choose CROSS_DEVICE; choose any presentation options (they don't matter)

  5. Request URI                 :
     $AR2_INSTRUCTIONS

  6. Credential select           : Select auto

The Holder posts the delegation grant to the Agent, which then presents it to the Merchant.

Press Ctrl-C to stop the demo, services and print logs.
============================================================================
EOF

while true; do
  sleep 1
done
