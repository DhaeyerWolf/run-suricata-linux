#!/usr/bin/env python3

"""
This script runs Suricata on a provided PCAP file using the specified Suricata rules,
extracts files to a local directory, and then scans those files using yara-python.
It also generates Pandas tables for Suricata alerts and YARA scan results,
shortens long output for readability, cleans up temporary files, and now produces an HTML
page visualizing network traffic from fast.log. In the visualization, nodes represent assets,
edges represent the connection traffic (with directional arrows), and when hovering over an edge,
the associated alert(s) are displayed (with counts if multiple occur).

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
import json


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
                     "YARA scanning on files extracted in ./suricata-logs/filestore/. Additionally, "
                     "an HTML page is generated to visualize the network traffic from fast.log."),
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
    def shorten_text_local(text, max_length=50):
        return text if len(text) <= max_length else text[:max_length] + "..."

    df_display = df_full.copy()
    df_display["filetype"] = df_display["filetype"].apply(lambda x: shorten_text_local(x, 40))
    df_display["yara match"] = df_display["yara match"].apply(lambda x: shorten_text_local(x, 40))
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


def generate_network_traffic_html(log_dir: Path):
    """
    Generate an HTML page that visualizes network traffic from fast.log.
    The visualization shows nodes (assets) and edges (connections) on the left.
    A persistent alert list is displayed on the right showing two columns: 
       "Alert Name" and "Count" (default sorted by count descending).
    A search box allows filtering the alert list by alert names.
    Clicking on a flow (edge) filters the alert list to only the alerts associated
    with that connection. Likewise, clicking on an alert row highlights in the graph
    only the flows (edges) that involve that alert, graying out the others.
    Clicking on Reset Filter (or deselecting) resets the graph to its default state.
    """
    fast_log = log_dir / "fast.log"
    if not fast_log.exists():
        print(f"{fast_log} does not exist. Skipping network traffic visualization.")
        return

    # Data structures for network graph and global alert aggregation.
    nodes = {}    # key = asset IP, value = node object with id and label
    edges = {}    # key = (src, dst), value = { "count": int, "alerts": { alert: count } }
    global_alerts = {}  # key = alert name, value = count

    # Regexes to extract alert text and network endpoints.
    alert_pattern = re.compile(r"\[\*\*\]\s*(.*?)\s*\[\*\*\]")
    traffic_pattern = re.compile(r"\{\s*(?P<protocol>\w+)\s*\}\s+(?P<src>[\d\.]+:\d+)\s+->\s+(?P<dst>[\d\.]+:\d+)")

    with open(fast_log, "r") as f:
        for line in f:
            alert_matches = alert_pattern.findall(line)
            alert_text = alert_matches[0] if alert_matches else "Unknown Alert"
            global_alerts[alert_text] = global_alerts.get(alert_text, 0) + 1

            traffic_match = traffic_pattern.search(line)
            if traffic_match:
                src_full = traffic_match.group("src")
                dst_full = traffic_match.group("dst")
                src_ip = src_full.split(":")[0]
                dst_ip = dst_full.split(":")[0]

                nodes[src_ip] = {"id": src_ip, "label": src_ip}
                nodes[dst_ip] = {"id": dst_ip, "label": dst_ip}

                edge_key = (src_ip, dst_ip)
                if edge_key not in edges:
                    edges[edge_key] = {"count": 0, "alerts": {}}
                edges[edge_key]["count"] += 1
                edges[edge_key]["alerts"][alert_text] = edges[edge_key]["alerts"].get(alert_text, 0) + 1

    nodes_list = list(nodes.values())
    edges_list = []
    edge_id_counter = 0
    for (src, dst), data in edges.items():
        alerts_arr = [{"name": alert, "count": count} for alert, count in data["alerts"].items()]
        alerts_tooltip = "<br>".join(f"{alert} ({cnt})" for alert, cnt in data["alerts"].items())
        edge_obj = {
            "id": f"edge_{edge_id_counter}",
            "from": src,
            "to": dst,
            "arrows": "to",
            "label": str(data["count"]),
            "title": alerts_tooltip,
            "alerts": alerts_arr
        }
        edges_list.append(edge_obj)
        edge_id_counter += 1

    global_alerts_list = sorted(
        [{"name": name, "count": count} for name, count in global_alerts.items()],
        key=lambda x: x["count"],
        reverse=True
    )

    import json
    nodes_json = json.dumps(nodes_list)
    edges_json = json.dumps(edges_list)
    global_alerts_json = json.dumps(global_alerts_list)

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Network Traffic &amp; Alert List Visualization</title>
  <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <style type="text/css">
    body {{
      font-family: Arial, sans-serif;
      margin: 0;
      padding: 0;
      display: flex;
      height: 100vh;
    }}
    #graphContainer {{
      flex: 2;
      border-right: 1px solid #ccc;
      padding: 10px;
      min-width: 400px;
    }}
    #alertContainer {{
      flex: 1;
      padding: 10px;
      overflow-y: auto;
      min-width: 300px;
    }}
    #network {{
      width: 100%;
      height: 600px;
      border: 1px solid lightgray;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
    }}
    th, td {{
      padding: 8px;
      text-align: left;
      border-bottom: 1px solid #ddd;
    }}
    th {{
      cursor: pointer;
      background-color: #f2f2f2;
    }}
    tr:hover {{
      background-color: #eaeaea;
    }}
    #resetBtn {{
      margin-bottom: 10px;
    }}
    #searchBox {{
      width: 95%;
      padding: 6px;
      margin-bottom: 10px;
      border: 1px solid #ccc;
    }}
    #noDataMessage {{
      color: red;
      font-weight: bold;
      margin-top: 20px;
    }}
  </style>
</head>
<body>
  <div id="graphContainer">
    <h2>Network Graph</h2>
    <div id="network"></div>
    <div id="noDataMessage"></div>
  </div>
  <div id="alertContainer">
    <h2>Alert List</h2>
    <input type="text" id="searchBox" placeholder="Search alerts...">
    <button id="resetBtn">Reset Filter</button>
    <table id="alertTable">
      <thead>
         <tr>
           <th data-sort="name">Alert Name</th>
           <th data-sort="count">Count</th>
         </tr>
      </thead>
      <tbody id="alertTableBody"></tbody>
    </table>
  </div>
  <script type="text/javascript">
    // Parse JSON data logged from Python.
    var nodes = new vis.DataSet({nodes_json});
    var edges = new vis.DataSet({edges_json});
    console.log("Nodes:", nodes.get());
    console.log("Edges:", edges.get());
    var container = document.getElementById('network');
    var data = {{
      nodes: nodes,
      edges: edges
    }};
    var options = {{
      interaction: {{
        hover: true
      }},
      edges: {{
        arrows: {{
          to: {{
            enabled: true
          }}
        }},
        font: {{
          align: 'middle'
        }}
      }},
      physics: {{
        stabilization: true
      }}
    }};
    var network = new vis.Network(container, data, options);

    // Global alert list.
    var globalAlerts = {global_alerts_json};
    var currentAlerts = globalAlerts.slice();
    console.log("Global Alerts:", globalAlerts);

    // Function to render the alert table.
    function renderAlertTable(alerts) {{
      alerts.sort(function(a, b) {{
        return b.count - a.count;
      }});
      var tbody = document.getElementById('alertTableBody');
      tbody.innerHTML = "";
      alerts.forEach(function(item) {{
        var row = document.createElement("tr");
        row.setAttribute("data-alert-name", item.name);
        var cellName = document.createElement("td");
        cellName.textContent = item.name;
        var cellCount = document.createElement("td");
        cellCount.textContent = item.count;
        row.appendChild(cellName);
        row.appendChild(cellCount);
        row.addEventListener("click", function() {{
          filterGraphByAlert(item.name);
          var rows = document.querySelectorAll("#alertTableBody tr");
          rows.forEach(function(r) {{
            r.style.backgroundColor = "";
          }});
          this.style.backgroundColor = "#ffedcc";
        }});
        tbody.appendChild(row);
      }});
    }}

    renderAlertTable(currentAlerts);

    // Function to filter table rows by search input.
    function filterAlertsBySearch(searchTerm) {{
      var filtered = globalAlerts.filter(function(alert) {{
        return alert.name.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1;
      }});
      currentAlerts = filtered;
      renderAlertTable(currentAlerts);
    }}

    // Add event listener to the search box.
    document.getElementById("searchBox").addEventListener("keyup", function() {{
      filterAlertsBySearch(this.value);
    }});

    // Function to filter graph edges based on an alert.
    function filterGraphByAlert(alertName) {{
      edges.forEach(function(edge) {{
         var hasAlert = false;
         if (edge.alerts && Array.isArray(edge.alerts)) {{
           edge.alerts.forEach(function(a) {{
             if (a.name === alertName) {{
               hasAlert = true;
             }}
           }});
         }}
         if (hasAlert) {{
            edges.update({{id: edge.id, color: {{color: "red", inherit: false}}}});
         }} else {{
            edges.update({{id: edge.id, color: {{color: "lightgray", inherit: false}}}});
         }}
      }});
    }}

    // Function to reset graph edges to default style.
    function resetGraphEdgeStyles() {{
      edges.forEach(function(edge) {{
         edges.update({{id: edge.id, color: {{}}}});
      }});
    }}

    // Networking events.
    network.on("selectEdge", function (params) {{
      if (params.edges.length > 0) {{
        var edgeId = params.edges[0];
        var edgeObj = edges.get(edgeId);
        if (edgeObj && edgeObj.alerts) {{
          currentAlerts = edgeObj.alerts.slice();
          renderAlertTable(currentAlerts);
        }}
      }}
    }});
    network.on("deselectEdge", function (params) {{
      currentAlerts = globalAlerts.slice();
      renderAlertTable(currentAlerts);
      resetGraphEdgeStyles();
    }});

    document.getElementById("resetBtn").addEventListener("click", function() {{
      network.unselectAll();
      currentAlerts = globalAlerts.slice();
      renderAlertTable(currentAlerts);
      resetGraphEdgeStyles();
      var rows = document.querySelectorAll("#alertTableBody tr");
      rows.forEach(function(r) {{
         r.style.backgroundColor = "";
      }});
      document.getElementById("searchBox").value = "";
    }});

    var headers = document.querySelectorAll("th[data-sort]");
    headers.forEach(function(header) {{
      header.addEventListener("click", function() {{
        var sortKey = this.getAttribute("data-sort");
        if (this.getAttribute("data-order") === "desc") {{
          this.setAttribute("data-order", "asc");
          currentAlerts.sort(function(a, b) {{
            if (sortKey === "count") return a.count - b.count;
            return a.name.localeCompare(b.name);
          }});
        }} else {{
          this.setAttribute("data-order", "desc");
          currentAlerts.sort(function(a, b) {{
            if (sortKey === "count") return b.count - a.count;
            return b.name.localeCompare(a.name);
          }});
        }}
        renderAlertTable(currentAlerts);
      }});
    }});

    if (nodes.get().length === 0 || edges.get().length === 0) {{
      document.getElementById("noDataMessage").textContent = "Warning: No network data found.";
    }}
  </script>
</body>
</html>
"""
    output_html = log_dir / "network_traffic.html"
    with open(output_html, "w") as f:
        f.write(html_content)
    print("Network traffic visualization generated: {}".format(output_html))

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

    # Generate network traffic visualization HTML using fast.log
    print("Generating network traffic visualization HTML...")
    generate_network_traffic_html(log_dir)


if __name__ == "__main__":
    main()