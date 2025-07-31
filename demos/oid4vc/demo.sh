#!/usr/bin/env bash

cleanup() {
  if [ -f "$OUTPUT_DIR/issuer.log" ]; then
    echo Issuer logs:
    cat "$OUTPUT_DIR/issuer.log"
  fi
  if [ -n "$issuer_pid" ]; then
    kill "$issuer_pid" 2>/dev/null
    echo "Terminated issuer process (PID: $issuer_pid)"
  fi

  if [ -f "$OUTPUT_DIR/verifier.log" ]; then
    echo Verifier logs:
    cat "$OUTPUT_DIR/verifier.log"
  fi
  if [ -n "$verifier_pid" ]; then
    kill "$verifier_pid" 2>/dev/null
    echo "Terminated verifier process (PID: $verifier_pid)"
  fi
}

trap cleanup EXIT

OUTPUT_DIR=./output
mkdir -p $OUTPUT_DIR

export RUST_LOG=debug

cargo run --manifest-path ./issuer/Cargo.toml -F ci_demo > "$OUTPUT_DIR/issuer.log" 2>&1 &
issuer_pid=$!
timeout 10m bash -c \
  "tail -n0 -f \"$OUTPUT_DIR/issuer.log\" | sed '/starting service/ q'" \
  || { echo "Issuer start timeout!"; exit 1; }
echo "Issuer started (PID: $issuer_pid)"

cargo run --manifest-path ./verifier/Cargo.toml > "$OUTPUT_DIR/verifier.log" 2>&1 &
verifier_pid=$!
timeout 10m bash -c \
  "tail -n0 -f \"$OUTPUT_DIR/verifier.log\" | sed '/starting service/ q'" \
  || { echo "Issuer start timeout!"; exit 1; }
echo "Verifier started (PID: $verifier_pid)"


# Run demos

presentation_flow_types=(
  "SAME_DEVICE"
  "CROSS_DEVICE"
)

presentation_query_types=(
  "DCQL"
  "DEFINITION"
)

for presentation_flow in "${presentation_flow_types[@]}"
do
  for presentation_query in "${presentation_query_types[@]}"
  do
    PRESENTATION_FLOW="$presentation_flow" \
    PRESENTATION_QUERY="$presentation_query" \
    cargo run --manifest-path ./holder/Cargo.toml -F noninteractive \
      || { echo "Holder failed!"; exit 1; }
  done
done
