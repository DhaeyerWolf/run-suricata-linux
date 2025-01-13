#!/bin/bash

# Function to display help menu
show_help() {
    echo "Usage: $0 [options] <pcap_file> <rules_directory>"
    echo
    echo "Options:"
    echo "  -d, --disable-flow   Remove flow directives from rules. (May break rules, but can show more results)"
    echo "  -v                   Enable verbose mode."
    echo "  -vv                  Enable more verbose mode."
    echo "  -vvv                 Enable maximum verbosity."
    echo "  -h                   Show this help message and exit."
    exit 0
}

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

# Initialize variables for options
DISABLE_FLOW=false
VERBOSE_LEVEL=0

# Parse options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h)
            show_help
            ;;
        -d|--disable-flow)
            DISABLE_FLOW=true
            shift
            ;;
        -v)
            VERBOSE_LEVEL=$((VERBOSE_LEVEL + 1))
            shift
            ;;
        -vv)
            VERBOSE_LEVEL=2
            shift
            ;;
        -vvv)
            VERBOSE_LEVEL=3
            shift
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "Invalid option: $1" >&2
            show_help
            ;;
        *)
            break
            ;;
    esac
done

# Check for the required arguments
if [ $# -ne 2 ]; then
    echo "Usage: $0 [options] <pcap_file> <rules_directory>"
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

# Prepare logging directory for new execution
rm -rf ./suricata-logs/
mkdir ./suricata-logs/
touch ./suricata-logs/fast.log

# Extract disabled rules and write them to rules.disabled
grep -h '^#a' "$ABS_RULES_DIR"/*.rules > ./suricata-logs/rules.disabled

# Create a temporary file to compile all rules
if [ "$DISABLE_FLOW" = true ]; then
    grep -hEv '^\s*$|^\s*#' "$ABS_RULES_DIR"/*.rules | sed 's/flow:[^;]*;//g' > ./suricata.rules
else
    grep -hEv '^\s*$|^\s*#' "$ABS_RULES_DIR"/*.rules > ./suricata.rules
fi

# Construct verbosity option
VERBOSE_OPTION=""
if [ "$VERBOSE_LEVEL" -eq 1 ]; then
    VERBOSE_OPTION="-v"
elif [ "$VERBOSE_LEVEL" -eq 2 ]; then
    VERBOSE_OPTION="-vv"
elif [ "$VERBOSE_LEVEL" -eq 3 ]; then
    VERBOSE_OPTION="-vvv"
fi

# Run Suricata with the provided PCAP file, temporary configuration, and compiled rules
echo "Running Suricata on $PCAP_FILE with rules from $ABS_RULES_DIR ..."
suricata -c ./suricata.yaml -r "$PCAP_FILE" -s ./suricata.rules -l ./suricata-logs/ $VERBOSE_OPTION

# Clean up the temporary rules file
rm -f ./suricata.rules

echo "Parsing rules ..."
# Parse the fast.log to count alert occurrences and output to alert-overview.log and screen
{
    echo "| Rule SID + Name                                                | Count |"
    echo "|---------------------------------------------------------------|-------|"
    grep '\[\*\*\]' ./suricata-logs/fast.log | sed 's/.*\[\*\*\] \(.*\) \[\*\*\].*/\1/' | sort | uniq -c | sort -rn | awk '{ printf "| %-61s | %-5d |\n", substr($0, index($0, $2)), $1 }'
} > ./suricata-logs/alert-overview.log

# Display the alert overview
cat ./suricata-logs/alert-overview.log
echo
echo

echo "Parsing extracted files ..."
# Remove all empty directories from the filestore directory
find ./suricata-logs/filestore -type d -empty -delete

# Analyze files in the filestore directory and create a markdown table
{
    echo "| Filename/SHA256sum                                           | Filetype |"
    echo "|--------------------------------------------------------------|----------|"
    find ./suricata-logs/filestore -mindepth 2 -maxdepth 2 -type f | while read -r file; do
        sha256=$(sha256sum "$file" | awk '{print $1}')
        filetype=$(file -b "$file")
        printf "| %-60s | %-8s |\n" "$sha256" "$filetype"
    done | sort -t '|' -k3,3
} > ./suricata-logs/filetype-overview.log

# Display the filetype overview
cat ./suricata-logs/filetype-overview.log
