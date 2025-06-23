#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
# port2ctree.py
# Convert an Nmap/Rustscan result file into a Cherrytree .ctd file
# Created by kyssK00l 🐙
# ─────────────────────────────────────────────────────────────

import re
import sys
import os

def parse_ports(filename):
    ports = set()
    pattern = re.compile(r'^(\d+)/(tcp|udp)\s+open\s+(\S+)')
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            match = pattern.match(line.strip())
            if match:
                port, proto, service = match.groups()
                ports.add((int(port), proto, service))
    return sorted(ports)

def generate_ctd(ports, output_file):
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<cherrytree>\n')
        f.write('  <node name="Open Ports" custom_icon_id="0">\n')
        for port, proto, service in ports:
            f.write(f'    <node name="Port {port}/{proto} - {service}" custom_icon_id="0">\n')
            f.write('      <rich_text><![CDATA[\n')
            f.write(f'<b>Port:</b> {port}<br/>\n')
            f.write(f'<b>Protocol:</b> {proto}<br/>\n')
            f.write(f'<b>Service:</b> {service}<br/>\n')
            f.write(f'<b>Nmap command:</b> <code>nmap -p {port}/{proto} -sV -sC [IP]</code>\n')
            f.write('      ]]></rich_text>\n')
            f.write('    </node>\n')
        f.write('  </node>\n</cherrytree>\n')
    print(f"✅ Cherrytree file generated: {output_file}")

def show_help():
    help_text = """
Usage: port2ctree <scan_output.txt>

Description:
  This tool parses open ports from a Nmap or Rustscan output and generates a Cherrytree-compatible .ctd file.
  It creates one node per open port, including protocol, service, and a ready-to-use Nmap command.

Steps after generation:
  1. Open Cherrytree.
  2. Select the node where you want to insert the ports (important!).
  3. Go to 'File' > 'Import'.
  4. Choose 'Cherrytree XML File (.ctd)' and select the generated file: ports_nodes.ctd
  5. The tree will be populated with one node per open port under the selected node.

Example:
  port2ctree nmap_scan.txt
"""
    print(help_text)
    sys.exit(0)

def main():
    if len(sys.argv) != 2 or sys.argv[1] in ('-h', '--help'):
        show_help()

    input_file = sys.argv[1]
    output_file = "ports_nodes.ctd"

    if not os.path.isfile(input_file):
        print(f"⛔ File not found: {input_file}")
        sys.exit(1)

    ports = parse_ports(input_file)
    if not ports:
        print("⚠️ No open ports found.")
        sys.exit(0)

    generate_ctd(ports, output_file)

if __name__ == "__main__":
    main()

