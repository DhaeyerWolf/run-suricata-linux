# New version - Suricata + YARA

This tool automates the scanning of PCAP files using Suricata and yara-python. It performs the following tasks:

- **Suricata Analysis:**  
  Runs Suricata on a provided PCAP file using a specified set of Suricata rules.  
  It extracts files and logs alerts into the *fast.log* file.

- **YARA Scanning:**  
  Scans the extracted files using yara-python.  
  If a YARA rules file is not provided or found, the tool downloads and compiles the full YARA HQ rules set.  

## Installation

Ensure that your system has Python 3.6 or later. Install required Python packages:

```bash
pip install pandas yara-python
```

You will need to have suricata installed. The script checks upon startup if suricata is installed. **If suricata is not installed the script will attempt to install suricata** using the following repository: `ppa:oisf/suricata-stable` 
**Note:** You may need administrative privileges for installation.

## Usage

Run the script from the command line:

```bash
./run-suricata.py [options] <pcap_file> <rules_directory>
```

### Options

- `-d, --disable-flow`  
  Remove flow directives from Suricata rules before use. (May break some rules but can allow for more results.)

- `-v`  
  Increase verbosity. Use `-vv` or `-vvv` for higher verbosity levels.

- `--yara-rules`  
  Path to your YARA rules file. If not provided or not found, the full YARA HQ rules set will be downloaded, compiled, and used.

### Example

```bash
./run-suricata.py -d example.pcap ./Rules/
```

## Output

- **Alert Log:**  
  A Suricata alerts overview is generated and saved as `suricata-logs/alerts_results.log`.

- **YARA Log:**  
  A shortened YARA results table is written to `suricata-logs/yara_results.log`.

- **CSV Output:**  
  The full YARA results table (with complete data, not just the shortened version) is exported as `suricata-logs/yara_results.csv`.

- **YARA Rules Copy:**  
  A copy of the active YARA rules file is stored as `suricata-logs/yara_rules.yar`.

- **Temporary Files:**  
  Any temporary combined YARA rules file is removed after use.

# Old version - Suricata only

## run-suricata-linux
This script provides a preconfigured `suricata.yaml` file to facilitate the detection of custom Suricata rules on a specified PCAP file.

## Usage
To use the script run the command: `./suricate-run.sh <pcap_file> <rules_directory>`

The script utilizes the default ruleset located at `/var/lib/suricata/rules` in addition to the custom rules specified in the command line.

## Installation
You will need to have suricata installed. The script checks upon startup if suricata is installed. **If suricata is not installed the script will attempt to install suricata** using the following repository: `ppa:oisf/suricata-stable`

# Notes
A few important notes about the `suricata.yaml` file:
- This file has been modified so that both `$HOME_NET` & `$EXTERNAL_NET` are set to `any`. This will trigger a lot of rules, or even break some rules (as it basically will ignore any rule that takes advantage of this); if this is too verbose. Please set `HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"` & `EXTERNAL_NET: "!$HOME_NET"`