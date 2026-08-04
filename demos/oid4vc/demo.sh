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

# Pre-build the demo binaries up front so the (potentially slow, cache-cold)
# compile happens here rather than inside the timed start-up waits below, where
# it can exceed the `timeout 10m` window and be reported as a start timeout.
cargo build --manifest-path ./issuer/Cargo.toml -F ci_demo || { echo "Issuer build failed!"; exit 1; }
cargo build --manifest-path ./verifier/Cargo.toml || { echo "Verifier build failed!"; exit 1; }
cargo build --manifest-path ./holder/Cargo.toml -F noninteractive || { echo "Holder build failed!"; exit 1; }

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

# Same device flow

presentation_query_types=(
  "DCQL"
  "DEFINITION"
)

presentation_response_types=(
  "VP_TOKEN_ID_TOKEN"
  "VP_TOKEN"
)

presentation_response_modes=(
  "FRAGMENT"
  "FRAGMENT_JWT"
)

for presentation_query_type in "${presentation_query_types[@]}"
do
  for presentation_response_type in "${presentation_response_types[@]}"
  do
    for presentation_response_mode in "${presentation_response_modes[@]}"
    do
      echo Running flow: "SAME_DEVICE"\; \
        presentation query: "${presentation_query_type}"\; \
        presentation response type: "${presentation_response_type}"\; \
        presentation response mode: "${presentation_response_mode}"

      PRESENTATION_FLOW="SAME_DEVICE" \
      PRESENTATION_QUERY="$presentation_query_type" \
      PRESENTATION_RESPONSE_TYPE="$presentation_response_type" \
      PRESENTATION_RESPONSE_MODE="$presentation_response_mode" \
      cargo run --manifest-path ./holder/Cargo.toml -F noninteractive \
        || { echo "Holder failed!"; exit 1; }
    done
  done
done

# Cross device flow

presentation_response_modes=(
  "DIRECT_POST"
  "DIRECT_POST_JWT"
)

for presentation_query_type in "${presentation_query_types[@]}"
do
  for presentation_response_type in "${presentation_response_types[@]}"
  do
    for presentation_response_mode in "${presentation_response_modes[@]}"
    do
      echo Running flow: "CROSS_DEVICE"\; \
        presentation query: "${presentation_query_type}"\; \
        presentation response type: "${presentation_response_type}"\; \
        presentation response mode: "${presentation_response_mode}"

      PRESENTATION_FLOW="CROSS_DEVICE" \
      PRESENTATION_QUERY="$presentation_query_type" \
      PRESENTATION_RESPONSE_TYPE="$presentation_response_type" \
      PRESENTATION_RESPONSE_MODE="$presentation_response_mode" \
      cargo run --manifest-path ./holder/Cargo.toml -F noninteractive \
        || { echo "Holder failed!"; exit 1; }
    done
  done
done

echo "Demo finished"
