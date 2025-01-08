# run-suricata-linux
This script provides a preconfigured `suricata.yaml` file to facilitate the detection of custom Suricata rules on a specified PCAP file.

# Usage
To use the script run the command: `./suricate-run.sh <pcap_file> <rules_directory>`

The script utilizes the default ruleset located at `/var/lib/suricata/rules` in addition to the custom rules specified in the command line.


# Installation
You will need to have suricata installed. The script checks upon startup if suricata is installed. **If suricata is not installed the script will attempt to install suricata** using the following repository: `ppa:oisf/suricata-stable`