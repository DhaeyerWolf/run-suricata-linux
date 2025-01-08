#!/bin/bash

# Function to install Suricata if not installed
install_suricata() {
    echo "Suricata is not installed. Installing Suricata..."
    sudo apt update

    # Attempt to install Suricata
    if ! sudo apt install -y suricata; then
        echo "Suricata package not found in default repositories. Adding PPA..."
        
        # Add the PPA for Suricata
        sudo add-apt-repository -y ppa:oisf/suricata-stable
        sudo apt update
        
        # Try installing Suricata again
        if ! sudo apt install -y suricata; then
            echo "Failed to install Suricata from PPA. Exiting."
            exit 1
        fi
    fi

    echo "Suricata installed successfully."
}

# Check if Suricata is installed
if ! command -v suricata &> /dev/null; then
    install_suricata
else
    echo "Suricata is already installed."
fi

# Check for the required arguments
if [ $# -ne 2 ]; then
    echo "Usage: $0 <pcap_file> <rules_directory>"
    exit 1
fi

PCAP_FILE=$1
RULES_DIR=$2

# Convert the rules directory to an absolute path
ABS_RULES_DIR=$(realpath "$RULES_DIR")
echo "Absolute rules directory: $ABS_RULES_DIR"

# Verify the pcap file exists
if [ ! -f "$PCAP_FILE" ]; then
    echo "PCAP file $PCAP_FILE does not exist. Exiting."
    exit 1
fi

# Verify the rules directory exists
if [ ! -d "$ABS_RULES_DIR" ]; then
    echo "Rules directory $ABS_RULES_DIR does not exist. Exiting."
    exit 1
fi

# Create a temporary file to compile all rules
cat "$ABS_RULES_DIR"/*.rules > ./suricata.rules

# Prepare logging directory for new execution
rm -rf ./suricata-logs/
mkdir ./suricata-logs/
touch ./suricata-logs/fast.log

# Run Suricata with the provided PCAP file, temporary configuration, and compiled rules
echo "Running Suricata on $PCAP_FILE with rules from $ABS_RULES_DIR..."
suricata -c ./suricata.yaml -r "$PCAP_FILE" -s ./suricata.rules -l ./suricata-logs/

# Display triggered alerts from the fast.log
echo "Triggered rules (from fast.log, for more detail, check the ./suricata-logs/ directory):"
cat ./suricata-logs/fast.log

# Clean up the temporary rules file
rm -f "$TEMP_RULES_FILE"
