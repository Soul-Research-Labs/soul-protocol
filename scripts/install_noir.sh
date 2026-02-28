#!/bin/bash

# Add local tools to PATH
export PATH="$(pwd)/tools/nargo:$(pwd)/tools/bb:$HOME/.nargo/bin:$HOME/.bb/bin:$PATH"

# Setup Noir (nargo)
if ! command -v nargo &> /dev/null; then
    echo "Installing Noir (nargo)..."
    mkdir -p /tmp/zaseon_home
    # Use custom HOME to avoid permission issues
    CUSTOM_HOME="/tmp/zaseon_home"
    export HOME=$CUSTOM_HOME
    curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
    export PATH="$CUSTOM_HOME/.nargo/bin:$PATH"
    noirup
    # Move to workspace for persistence
    mkdir -p tools/nargo
    cp $CUSTOM_HOME/.nargo/bin/nargo tools/nargo/
else
    echo "Noir (nargo) already installed: $(nargo --version)"
fi

# Setup Barretenberg (bb)
if ! command -v bb &> /dev/null; then
    echo "Installing Barretenberg (bb)..."
    mkdir -p /tmp/zaseon_home
    CUSTOM_HOME="/tmp/zaseon_home"
    export HOME=$CUSTOM_HOME
    curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/cpp/installation/install | bash
    export PATH="$CUSTOM_HOME/.bb/bin:$PATH"
    # bbup might be in .bb root in some versions of the install script
    if [ -f "$CUSTOM_HOME/.bb/bbup" ]; then
        $CUSTOM_HOME/.bb/bbup -v 0.55.0
    else
        bbup -v 0.55.0
    fi
    # Move to workspace for persistence
    mkdir -p tools/bb
    cp $CUSTOM_HOME/.bb/bb tools/bb/
else
    echo "Barretenberg (bb) already installed: $(bb --version)"
fi

echo "Noir toolchain setup complete."
