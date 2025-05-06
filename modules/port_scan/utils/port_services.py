import socket

well_known_ports = {
    1: "TCPMUX",
    7: "Echo",
    9: "Discard",
    13: "Daytime",
    17: "QOTD",
    19: "CHARGEN",
    20: "FTP data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    443: "HTTPS",
    445: "SMB",
    514: "Syslog",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    5432: "PostgreSQL",
}

def get_service_name(port):
    try:
        port = int(port)
    except ValueError:
        return "Unknown"

    service = well_known_ports.get(port)

    if service is None:
        try:
            service = socket.getservbyport(port)
        except OSError:
            service = "Unknown"
    
    return service