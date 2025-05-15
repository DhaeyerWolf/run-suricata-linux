#!/usr/bin/env python3
"""
This script runs Suricata on a provided PCAP file using the specified Suricata rules,
extracts files to a local directory, and then scans those files using yara-python.
It also generates Pandas tables for Suricata alerts and YARA scan results,
shortens long output for readability, and cleans up temporary files.

Usage:
    ./run-suricata.py [options] <pcap_file> <rules_directory>

Options:
    -d, --disable-flow   Remove flow directives from rules.
    -v                   Increase verbosity (use -vv or -vvv for higher verbosity).
    --yara-rules         Path to YARA rules file. If not provided or not found,
                         the full YARA HQ rules will be downloaded and used.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

import pandas as pd
import yara


def shorten_text(text, max_length=50):
    """Shorten text to a maximum length."""
    if text is None:
        return text
    return text if len(text) <= max_length else text[:max_length] + "..."


def install_suricata():
    """Install Suricata using apt if it is not already installed."""
    print("Installing Suricata...")
    try:
        subprocess.run(["sudo", "apt", "update"], check=True)
    except subprocess.CalledProcessError:
        print("Failed to update apt. Exiting.")
        sys.exit(1)
    result = subprocess.run(["sudo", "apt", "install", "-y", "suricata"])
    if result.returncode != 0:
        try:
            subprocess.run(["sudo", "add-apt-repository", "-y", "ppa:oisf/suricata-stable"], check=True)
            subprocess.run(["sudo", "apt", "update"], check=True)
        except subprocess.CalledProcessError:
            print("Failed to add PPA or update apt. Exiting.")
            sys.exit(1)
        result = subprocess.run(["sudo", "apt", "install", "-y", "suricata"])
        if result.returncode != 0:
            print("Failed to install Suricata. Exiting.")
            sys.exit(1)
    print("Suricata installed successfully.")


def check_suricata_installed():
    """Check if Suricata is installed; if not, install it."""
    if shutil.which("suricata") is None:
        install_suricata()
    else:
        print("Suricata is already installed.")


def ensure_yara_rules(yara_rules_path: Path) -> (Path, bool):
    """
    Ensure that a YARA rules file exists.
    If not, download and combine full YARA HQ rules.
    Returns a tuple (rules_path, temp_rule_used)
    """
    temp_rule_used = False
    if not yara_rules_path.is_file():
        print(f"YARA rules file {yara_rules_path} not found.")
        print("Downloading full YARA HQ rules set...")
        url = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip"
        local_zip = Path("yara-forge-rules-full.zip")
        try:
            urllib.request.urlretrieve(url, local_zip)
        except Exception as e:
            print(f"Failed to download YARA rules: {e}")
            sys.exit(1)
        extract_dir = Path("yara_rules_extracted")
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        extract_dir.mkdir()
        with zipfile.ZipFile(local_zip, "r") as zip_ref:
            zip_ref.extractall(extract_dir)
        combined_rules = ""
        for yar_file in extract_dir.rglob("*.yar"):
            try:
                with open(yar_file, "r") as f:
                    combined_rules += f.read() + "\n"
            except Exception as e:
                print(f"Error reading {yar_file}: {e}")
        combined_path = Path("combined_yara_rules.yar")
        with open(combined_path, "w") as f:
            f.write(combined_rules)
        local_zip.unlink()
        shutil.rmtree(extract_dir)
        print(f"Combined YARA rules saved to {combined_path}.")
        yara_rules_path = combined_path
        temp_rule_used = True
    return yara_rules_path, temp_rule_used


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=("Run Suricata on a PCAP file with the supplied Suricata rules and perform "
                     "YARA scanning on files extracted in ./suricata-logs/filestore/."),
        usage="%(prog)s [options] <pcap_file> <rules_directory>"
    )
    parser.add_argument("pcap_file", help="Path to the PCAP file.")
    parser.add_argument("rules_directory", help="Directory containing Suricata rule files.")
    parser.add_argument("-d", "--disable-flow",
                        action="store_true", help="Remove flow directives from rules.")
    parser.add_argument("-v", dest="verbose", action="count", default=0,
                        help="Increase verbosity (use -vv or -vvv for higher verbosity).")
    parser.add_argument("--yara-rules", default="yara_rules.yar",
                        help=("Path to YARA rules file. If not provided or not found, the full YARA HQ rules "
                              "will be downloaded and used."))
    return parser.parse_args()


def prepare_logging_directory() -> Path:
    """Prepare the suricata-logs directory and its filestore subdirectory."""
    log_dir = Path("./suricata-logs")
    if log_dir.exists():
        shutil.rmtree(log_dir)
    log_dir.mkdir()
    (log_dir / "fast.log").touch()
    filestore = log_dir / "filestore"
    filestore.mkdir()
    return log_dir


def compile_disabled_rules(rules_dir: Path, output_file: Path):
    """Compile disabled rules from all .rules files into a single file."""
    disabled_rules = []
    for rule_file in rules_dir.glob("*.rules"):
        with open(rule_file, "r") as f:
            for line in f:
                if line.startswith("#a"):
                    disabled_rules.append(line)
    with open(output_file, "w") as outf:
        outf.writelines(disabled_rules)


def compile_rules(rules_dir: Path, output_file: Path, disable_flow: bool):
    """Compile active rules from all .rules files, optionally removing flow directives."""
    compiled_rules = []
    for rule_file in rules_dir.glob("*.rules"):
        with open(rule_file, "r") as f:
            for line in f:
                if re.match(r"^\s*$", line) or re.match(r"^\s*#", line):
                    continue
                if disable_flow:
                    line = re.sub(r'flow:[^;]*;', '', line)
                compiled_rules.append(line)
    with open(output_file, "w") as outf:
        outf.writelines(compiled_rules)


def run_suricata(pcap_file: str, rules_file: str, log_dir: Path, verbose_option: str):
    """Run Suricata with the given PCAP and rules, logging output to log_dir."""
    cmd = [
        "suricata",
        "-c", "./suricata.yaml",
        "-r", pcap_file,
        "-s", rules_file,
        "-l", str(log_dir)
    ]
    if verbose_option:
        cmd.append(verbose_option)
    print(f"Running Suricata on {pcap_file} using rules from {rules_file}...")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError:
        print("Suricata scanning failed. Exiting.")
        sys.exit(1)


def create_alerts_table(log_dir: Path):
    """Parse the fast.log file and create a table of alerts."""
    fast_log = log_dir / "fast.log"
    if not fast_log.exists():
        print(f"{fast_log} does not exist. Cannot parse alerts.")
        return
    alerts = {}
    alert_regex = re.compile(r"\[\*\*\]\s*(.*?)\s*\[\*\*\]")
    with open(fast_log, "r") as f:
        for line in f:
            for alert in alert_regex.findall(line):
                key = alert.strip()
                alerts[key] = alerts.get(key, 0) + 1
    if alerts:
        df = pd.DataFrame(list(alerts.items()), columns=["Rule SID + Name", "Count"])
        df.sort_values(by="Count", ascending=False, inplace=True)
        print("Alert Overview:")
        try:
            alerts_table = df.to_markdown(index=False)
        except ImportError:
            alerts_table = df.to_string(index=False)
        print(alerts_table)
        with open(log_dir / "alerts_results.log", "w") as f:
            f.write(alerts_table)
    else:
        print("No alerts found in fast.log.")


def remove_empty_directories(directory: Path):
    """Recursively remove empty directories."""
    for dirpath, _, _ in os.walk(directory, topdown=False):
        p = Path(dirpath)
        try:
            if not any(p.iterdir()):
                p.rmdir()
        except Exception as e:
            print(f"Failed to remove empty directory {p}: {e}")


def create_yara_results_table(rules_file: Path, filestore: Path, log_dir: Path):
    """
    Scan each file in filestore using yara-python, then:
      - Create a shortened table for display and log file.
      - Export a CSV file with the full data (not shortened).
    """
    try:
        rules = yara.compile(filepath=str(rules_file))
    except yara.YaraError as e:
        print(f"Failed to compile YARA rules: {e}")
        return

    rows = []
    for file in filestore.rglob("*"):
        if file.is_file():
            file_id = file.name  # assuming file name is its SHA256 sum
            try:
                filetype_full = subprocess.check_output(["file", "-b", str(file)], text=True).strip()
            except subprocess.CalledProcessError:
                filetype_full = "Unknown"
            try:
                matches = rules.match(filepath=str(file))
            except yara.Error as e:
                print(f"Error scanning file {file}: {e}")
                matches = []
            rule_matches_full = ""
            if matches:
                rule_names = [match.rule for match in matches if match.rule]
                rule_matches_full = ", ".join(rule_names)
            rows.append({
                "filename/sha256sum": file_id,
                "filetype": filetype_full,
                "yara match": rule_matches_full
            })

    df_full = pd.DataFrame(rows)
    if df_full.empty:
        print("No files found in filestore for YARA scanning.")
        return

    # Create a display version with shortened text.
    def shorten_text(text, max_length=50):
        return text if len(text) <= max_length else text[:max_length] + "..."
        
    df_display = df_full.copy()
    df_display["filetype"] = df_display["filetype"].apply(lambda x: shorten_text(x, 40))
    df_display["yara match"] = df_display["yara match"].apply(lambda x: shorten_text(x, 40))
    df_display["has_match"] = df_display["yara match"].apply(lambda x: bool(x.strip()))
    df_display.sort_values(by=["has_match", "filetype"], ascending=[False, True], inplace=True)
    df_display.drop(columns=["has_match"], inplace=True)

    try:
        results_table_display = df_display.to_markdown(index=False)
    except ImportError:
        results_table_display = df_display.to_string(index=False)
    print("File Overview with YARA Results:")
    print(results_table_display)
    with open(log_dir / "yara_results.log", "w") as f:
        f.write(results_table_display)

    # Export the full table to a CSV file
    csv_path = log_dir / "yara_results.csv"
    df_full.to_csv(csv_path, index=False)
    print(f"Full YARA results exported to CSV: {csv_path}")

def main():
    # Ensure Suricata is installed.
    check_suricata_installed()

    args = parse_arguments()

    pcap_path = Path(args.pcap_file)
    if not pcap_path.is_file():
        print(f"PCAP file {args.pcap_file} does not exist. Exiting.")
        sys.exit(1)
    rules_dir = Path(args.rules_directory).resolve()
    if not rules_dir.is_dir():
        print(f"Rules directory {rules_dir} does not exist. Exiting.")
        sys.exit(1)
    print("Absolute rules directory:", str(rules_dir))

    log_dir = prepare_logging_directory()

    compile_disabled_rules(rules_dir, log_dir / "rules.disabled")
    temp_rules_file = Path("./suricata.rules")
    compile_rules(rules_dir, temp_rules_file, args.disable_flow)

    verbose_option = ""
    if args.verbose == 1:
        verbose_option = "-v"
    elif args.verbose == 2:
        verbose_option = "-vv"
    elif args.verbose >= 3:
        verbose_option = "-vvv"

    run_suricata(str(pcap_path), str(temp_rules_file), log_dir, verbose_option)
    if temp_rules_file.exists():
        temp_rules_file.unlink()

    print("Parsing Suricata alert logs ...")
    create_alerts_table(log_dir)

    print("Processing extracted files ...")
    filestore = log_dir / "filestore"
    if filestore.exists():
        remove_empty_directories(filestore)
    else:
        print(f"{filestore} does not exist. Skipping file analysis.")
        return

    yara_rules_path = Path(args.yara_rules)
    yara_rules_path, temp_rule_used = ensure_yara_rules(yara_rules_path)
    # Copy active YARA rules to the log folder.
    shutil.copy(yara_rules_path, log_dir / "yara_rules.yar")

    print("Creating YARA results overview table ...")
    create_yara_results_table(yara_rules_path, filestore, log_dir)

    # Remove temporary combined YARA rules file after use.
    if temp_rule_used and yara_rules_path.name == "combined_yara_rules.yar":
        try:
            os.remove(yara_rules_path)
            print(f"Removed temporary file {yara_rules_path}.")
        except Exception as e:
            print(f"Failed to remove temporary file {yara_rules_path}: {e}")


if __name__ == "__main__":
    main()
