#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
# port2ctree.py
# Convert an Nmap/Rustscan result file into a Cherrytree .ctd file
# Created by kyssK00l 🐙
# ─────────────────────────────────────────────────────────────

import re
import sys
import os

def get_service_icon(service, port=None):
    """Map services to Cherrytree icon IDs based on official icon definitions"""
    
    # Official Cherrytree icon mapping based on ct_const.h
    icon_map = {
        # Web Services (using linkweb icon)
        'http': 64,           'https': 64,          'www': 64,
        'http-proxy': 64,     'http-alt': 64,       'webcache': 64,
        'https-alt': 64,      'ssl': 64,            'tls': 64,
        
        # Remote Access & Shells (using correct shell icon 22)
        'ssh': 22,            'telnet': 22,         'rlogin': 22,
        'shell': 22,          'exec': 22,           'login': 22,
        'rsh': 22,            'telnet-alt': 22,     'rexec': 22,
        'cmd': 22,            'powershell': 22,     'bash': 22,
        'zsh': 22,            'csh': 22,            'ksh': 22,
        'fish': 22,           'tcsh': 22,           'dash': 22,
        
        # File Transfer (using correct file transfer icon 44)
        'ftp': 44,            'ftp-data': 44,       'ftps': 44,
        'sftp': 44,           'tftp': 44,           'scp': 44,
        'ftps-data': 44,      'ftp-alt': 44,        'ftps-implicit': 44,        
        
        # Mail Services (using mail icon - need to find email icon)
        'smtp': 25,           'pop3': 25,           'imap': 25,
        'pop2': 25,           'imaps': 25,          'pop3s': 25,
        'smtps': 25,          'submission': 25,     'esmtp': 25,
        'mail': 25,           'mtp': 25,
        
        # Database Services (using correct database icon 143)  
        'mysql': 143,         'postgresql': 143,    'postgres': 143,
        'mssql': 143,         'mssql-s': 143,       'sqlserver': 143,
        'oracle': 143,        'mongodb': 143,       'redis': 143,
        'memcached': 143,     'couchdb': 143,       'cassandra': 143,
        'neo4j': 143,         'influxdb': 143,      'clickhouse': 143,
        'mariadb': 143,       'sqlite': 143,        'db2': 143,
        'dynamodb': 143,      'elasticsearch': 143, 'solr': 143,
        'firebird': 143,      'sybase': 143,        'informix': 143,
        'cockroachdb': 143,   'timescaledb': 143,   'yugabytedb': 143,
        'arangodb': 143,      'orientdb': 143,      'rethinkdb': 143,
        'foundationdb': 143,  'etcd': 143,          'consul': 143,
        
        # Network Infrastructure (using network icon)
        'dns': 65,            'domain': 65,         'dhcp': 65,
        'bootp': 65,          'bootpc': 65,         'bootps': 65,
        'ntp': 65,            'sntp': 65,           'time': 65,
        'snmp': 65,           'snmp-trap': 65,      'snmptrap': 65,
        
        # Directory Services (using network icon)
        'ldap': 65,           'ldaps': 65,          'ldap-alt': 65,
        'kerberos': 65,       'kpasswd': 65,        'klogin': 65,
        'kshell': 65,         'kerberos-adm': 65,
        
        # File Sharing (using file transfer icon 44)
        'smb': 44,            'cifs': 44,           'netbios-ns': 44,
        'netbios-dgm': 44,    'netbios-ssn': 44,    'microsoft-ds': 44,
        'nfs': 44,            'rpcbind': 44,        'portmapper': 44,
        'mountd': 44,         'lockd': 44,          'samba': 44,
        
        # Remote Desktop (using shell icon for terminal services)
        'rdp': 22,            'ms-wbt-server': 22,  'terminal-server': 22,
        'vnc': 22,            'vnc-http': 22,       'vnc-server': 22,
        'rfb': 22,            'x11': 22,            'xserver': 22,
        
        # Development & API (using github/gitlab icons when appropriate)
        'git': 182,           'svn': 182,           'subversion': 182,
        'api': 64,            'rest': 64,           'soap': 64,
        'jsonrpc': 189,       'xmlrpc': 64,         'graphql': 189,
        'jenkins': 253,       'postman': 245,
        
        # DevOps & Cloud Services  
        'docker': 137,        'kubernetes': 139,    'ansible': 134,
        'aws': 135,           'azure': 136,         'gcp': 138,
        
        # Message Queues (using network icon)
        'rabbitmq': 65,       'amqp': 65,           'mqtt': 65,
        'kafka': 65,          'activemq': 65,       'zeromq': 65,
        
        # Programming Languages
        'php': 196,           'javascript': 188,    'js': 188,
        'json': 189,          'yaml': 190,          'css': 185,
        'csharp': 140,        'lua': 192,           'scala': 197,
        'swift': 198,         'markdown': 193,      'latex': 191,
        
        # Security & VPN (using network icon)
        'openvpn': 65,        'ipsec': 65,          'l2tp': 65,
        'pptp': 65,           'ikev2': 65,          'wireguard': 65,
        
        # Backup & File Sync Services (using file transfer icon 44)
        'rsync': 44,          'bacula': 44,         'amanda': 44,
        'veeam': 44,          'backup': 44,         'rsyncd': 44,
        'duplicati': 44,      'borgbackup': 44,     'rdiff-backup': 44,
        
        # Miscellaneous Services
        'unknown': 1,         'tcpwrapped': 1,      'filtered': 1,
        'closed': 1,          'unassigned': 1,      'reserved': 1,
    }
    
    # Category-based fallback icons using official Cherrytree icons
    def get_category_icon(service_name, port_num):
        """Determine icon based on service patterns and port ranges"""
        
        service_lower = service_name.lower()
        
        # High ports (>= 8000) - usually web/application services
        if port_num and port_num >= 8000:
            if any(web in service_lower for web in ['http', 'web', 'www', 'api', 'rest']):
                return 64  # linkweb icon
            return 38  # code icon for applications
        
        # Check for service name patterns
        if any(db in service_lower for db in ['sql', 'db', 'database', 'mongo', 'redis', 'elastic']):
            return 143  # Database icon
        
        if any(mail in service_lower for mail in ['mail', 'smtp', 'pop', 'imap']):
            return 25  # Mail fallback icon
            
        if any(file in service_lower for file in ['ftp', 'file', 'share', 'nfs', 'smb', 'transfer', 'sync']):
            return 44  # file transfer icon
            
        if any(net in service_lower for net in ['net', 'network', 'proxy', 'gateway']):
            return 65  # network icon
            
        if any(remote in service_lower for remote in ['ssh', 'telnet', 'shell', 'terminal']):
            return 22  # shell icon for terminals
            
        if any(desktop in service_lower for desktop in ['rdp', 'vnc', 'remote', 'desktop']):
            return 22  # shell icon for remote desktop
            
        # Default fallback
        return 1  # Generic service icon
    
    service_lower = service.lower()
    port_num = int(port) if port and str(port).isdigit() else None
    
    # First try exact match
    if service_lower in icon_map:
        return icon_map[service_lower]
    
    # Then try category-based matching
    return get_category_icon(service, port_num)

def parse_ports(filename):
    """
    Parse open ports from a scan output file.

    Args:
        filename (str): Path to the scan file

    Returns:
        list: Sorted list of (port, protocol, service) tuples

    Raises:
        FileNotFoundError: If the file doesn't exist
        PermissionError: If the file can't be read
        UnicodeDecodeError: If the file has encoding issues
    """
    ports = set()
    pattern = re.compile(r'^(\d+)/(tcp|udp)\s+open\s+(\S+)')

    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    match = pattern.match(line.strip())
                    if match:
                        port, proto, service = match.groups()
                        port_int = int(port)

                        # Validate port range
                        if not (0 < port_int <= 65535):
                            print(f"⚠️  Warning: Invalid port number {port_int} on line {line_num}, skipping")
                            continue

                        ports.add((port_int, proto, service))
                except ValueError as e:
                    print(f"⚠️  Warning: Could not parse port on line {line_num}: {e}")
                    continue

    except FileNotFoundError:
        print(f"⛔ Error: File not found: {filename}")
        raise
    except PermissionError:
        print(f"⛔ Error: Permission denied while reading: {filename}")
        raise
    except UnicodeDecodeError as e:
        print(f"⛔ Error: File encoding issue in {filename}: {e}")
        print("   Try converting the file to UTF-8 encoding")
        raise
    except IOError as e:
        print(f"⛔ Error: I/O error while reading {filename}: {e}")
        raise

    return sorted(ports)

def generate_ctb(ports, output_file):
    """
    Generate a Cherrytree XML file from parsed ports.

    Args:
        ports (list): List of (port, protocol, service) tuples
        output_file (str): Path to the output file

    Raises:
        PermissionError: If the output file can't be written
        OSError: If there's a disk space or I/O issue
    """
    import time
    timestamp = str(int(time.time()))

    # Change extension to .ctd for XML format
    if output_file.endswith('.ctb'):
        output_file = output_file.replace('.ctb', '.ctd')

    # Validate output path
    output_dir = os.path.dirname(output_file) or '.'
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as e:
            print(f"⛔ Error: Cannot create output directory {output_dir}: {e}")
            raise

    if not os.access(output_dir, os.W_OK):
        print(f"⛔ Error: No write permission for directory: {output_dir}")
        raise PermissionError(f"Cannot write to directory: {output_dir}")

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            try:
                f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
                f.write('<cherrytree>\n')
                f.write(
                    f'  <node unique_id="1534" master_id="0" name="Ports" '
                    f'prog_lang="custom-colors" tags="" readonly="0" nosearch_me="0" '
                    f'nosearch_ch="1" custom_icon_id="18" is_bold="0" foreground="" '
                    f'ts_creation="{timestamp}" ts_lastsave="{timestamp}">\n'
                )
                f.write('    <rich_text justification="left"></rich_text>\n')
                f.write('    <rich_text>Ports discovered from scan</rich_text>\n')
                unique_id = 1606
                for port, proto, service in ports:
                    icon_id = get_service_icon(service, port)
                    f.write(
                        f'    <node unique_id="{unique_id}" master_id="0" name="port {port}/{proto} - {service}" '
                        f'prog_lang="custom-colors" tags="" readonly="0" nosearch_me="0" '
                        f'nosearch_ch="0" custom_icon_id="{icon_id}" is_bold="0" foreground="" '
                        f'ts_creation="{timestamp}" ts_lastsave="{timestamp}"/>\n'
                    )
                    unique_id += 1
                f.write('  </node>\n')
                f.write('</cherrytree>\n')
            except IOError as e:
                print(f"⛔ Error: Failed to write to file (disk full?): {e}")
                raise

        print(f"✅ Cherrytree file generated: {output_file}")

    except PermissionError:
        print(f"⛔ Error: Permission denied while writing to: {output_file}")
        raise
    except OSError as e:
        print(f"⛔ Error: Cannot write to file {output_file}: {e}")
        raise
    except Exception as e:
        print(f"⛔ Error: Unexpected error while generating file: {e}")
        raise

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
    """Main entry point for the port2ctree CLI tool."""
    if len(sys.argv) != 2 or sys.argv[1] in ('-h', '--help'):
        show_help()

    input_file = sys.argv[1]
    output_file = "ports_nodes.ctd"

    # Validate input file exists
    if not os.path.exists(input_file):
        print(f"⛔ Error: File not found: {input_file}")
        sys.exit(1)

    # Validate it's a file, not a directory
    if not os.path.isfile(input_file):
        print(f"⛔ Error: {input_file} is not a file")
        sys.exit(1)

    # Check read permissions
    if not os.access(input_file, os.R_OK):
        print(f"⛔ Error: No read permission for file: {input_file}")
        sys.exit(1)

    # Check file size (warn if > 100MB)
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
    try:
        file_size = os.path.getsize(input_file)
        if file_size == 0:
            print(f"⛔ Error: File is empty: {input_file}")
            sys.exit(1)
        elif file_size > MAX_FILE_SIZE:
            print(f"⚠️  Warning: Large file ({file_size / (1024*1024):.1f} MB). This may take a while...")
    except OSError as e:
        print(f"⛔ Error: Cannot access file {input_file}: {e}")
        sys.exit(1)

    # Parse ports with error handling
    try:
        ports = parse_ports(input_file)
    except (FileNotFoundError, PermissionError, UnicodeDecodeError, IOError) as e:
        # Error already printed by parse_ports
        sys.exit(1)
    except Exception as e:
        print(f"⛔ Unexpected error while parsing file: {e}")
        sys.exit(1)

    if not ports:
        print("⚠️  Warning: No open ports found in the scan file.")
        print("   Make sure the file contains Nmap or Rustscan output with format:")
        print("   <port>/<protocol>  open  <service>")
        sys.exit(0)

    print(f"ℹ️  Found {len(ports)} open port(s)")

    # Generate output file with error handling
    try:
        generate_ctb(ports, output_file)
    except (PermissionError, OSError) as e:
        # Error already printed by generate_ctb
        sys.exit(1)
    except Exception as e:
        print(f"⛔ Unexpected error while generating output: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

