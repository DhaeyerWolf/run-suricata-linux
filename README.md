# run-suricata-linux
This script provides a preconfigured `suricata.yaml` file to facilitate the detection of custom Suricata rules on a specified PCAP file.

# Usage
To use the script run the command: `./suricate-run.sh <pcap_file> <rules_directory>`

The script utilizes the default ruleset located at `/var/lib/suricata/rules` in addition to the custom rules specified in the command line.

# Installation
You will need to have suricata installed. The script checks upon startup if suricata is installed. **If suricata is not installed the script will attempt to install suricata** using the following repository: `ppa:oisf/suricata-stable`

# Notes
A few important notes about the `suricata.yaml` file:
- This file has been modified so that both `$HOME_NET` & `$EXTERNAL_NET` are set to `any`. This will trigger a lot of rules (as it basically will ignore any rule that takes advantage of this); if this is too verbose. Please set `HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"` & `EXTERNAL_NET: "!$HOME_NET"`