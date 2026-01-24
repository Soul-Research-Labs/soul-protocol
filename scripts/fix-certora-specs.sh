#!/bin/bash
# Fix CVL 2 invariant syntax in Certora specs
# Invariants must end with semicolon

cd /Users/manishghimire/Downloads/Privacy\ Interoperability\ Layer/certora/specs

for f in *.spec; do
  echo "Processing $f..."
  # Add semicolon to invariant lines that don't have one
  sed -i '' -E 's/^(invariant [^;{]+)$/\1;/' "$f"
done

echo "Done fixing invariant syntax"
