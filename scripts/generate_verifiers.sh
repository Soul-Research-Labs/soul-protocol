#!/bin/bash

# Ensure toolchain is in PATH
export PATH="$(pwd)/tools/nargo:$(pwd)/tools/bb:$HOME/.nargo/bin:$HOME/.bb/bin:$PATH"
# Avoid permission issues in home
export HOME="/tmp/zaseon_home"

GENERATED_DIR="contracts/verifiers/generated"
mkdir -p "$GENERATED_DIR"

echo "Compiling Noir workspace..."
cd noir
nargo compile
cd ..

# Loop through all compiled circuits in target
# Note: nargo v0.35 workspace puts them in noir/target/<member>.json
for circuit_json in noir/target/*.json; do
    if [ -f "$circuit_json" ]; then
        circuit_name=$(basename "$circuit_json" .json)
        echo "Processing circuit: $circuit_name"
        
        vk_file="noir/target/${circuit_name}_vk"
        sol_file="noir/target/${circuit_name}_verifier.sol"
        
        # Generate VK
        bb write_vk -b "$circuit_json" -o "$vk_file"
        
        # Generate Solidity Verifier
        bb contract -k "$vk_file" -o "$sol_file"
        
        # Move and rename
        if [ -f "$sol_file" ]; then
            # CamelCase name for contract (e.g., state_transfer -> StateTransfer)
            target_contract_name=$(echo "$circuit_name" | awk -F_ '{for(i=1;i<=NF;i++) printf "%s", toupper(substr($i,1,1)) substr($i,2)}')"Verifier"
            target_file_name="${target_contract_name}.sol"
            
            # Replace UltraVerifier and BaseUltraVerifier with dynamic names
            sed "s/UltraVerifier/$target_contract_name/g" "$sol_file" > "$GENERATED_DIR/$target_file_name"
            echo "Generated $target_file_name"
        fi
    fi
done

echo "Noir verifier generation complete."
