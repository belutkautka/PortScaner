import random
import time
import socket

from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1, sr
ports = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 43: "WHOIS", 53: "DNS", 80: "http",
        115: "SFTP", 123: "NTP", 143: "IMAP", 161: "SNMP",
        179: "BGP", 443: "HTTPS", 445: "MICROSOFT-DS",
        514: "SYSLOG", 515: "PRINTER", 993: "IMAPS",
        995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
        1433: "SQL Server", 1723: "PPTP", 3128: "HTTP",
        3268: "LDAP", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 8080: "Tomcat", 10000: "Webmin"}
class scaner:

    @staticmethod
    def scan_tcp_port(ip, port, timeout,verbose,guess):
            begin_time = time.time()
            src_port = random.randint(1025, 65534)
            response = sr1(IP(dst=ip) / TCP(sport=src_port, dport=port, flags="S"), timeout=timeout,verbose=0)
            if not response is None and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                sr(IP(dst=ip) / TCP(sport=src_port, dport=port, flags='R'), timeout=timeout, verbose=0)
                res=""
                if guess == True:
                    if port in ports.keys():
                        res=ports[port]
                    else:
                        res="-"

                print(f"TCP {port}"
                      f"{' ' + '%.3f' % (response.getlayer(TCP).time - begin_time) if verbose == True else ''}"
                      f" {res}\n")

    @staticmethod
    def socket_scan_tcp_port(ip, port, timeout, verbose,guess):
                    begin_time = time.time()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    try:
                        sock.connect((ip, port))
                    except socket.error:
                        pass
                    else:
                        res=""
                        if guess == True:
                            if port in ports.keys():
                                res = ports[port]
                            else:
                                res = "-"

                        print(f"TCP {port}"
                                  f"{' ' + '%.3f' % (time.time() - begin_time) if verbose == True else ''}"f" {res}\n")
                        sock.close()

    @staticmethod
    def scan_udp_port(ip, port, timeout,verbose,guess):
        begin_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        socket.setdefaulttimeout(timeout)
        try:
            result = sock.connect_ex((ip, port))
        except socket.error:
            pass
        else:
            res=""
            if guess == True:
                if port in ports.keys():
                    res = ports[port]
                else:
                    res = "-"

            print(f"UDP {port}"
                  f"{' ' + '%.3f' % (time.time() - begin_time) if verbose == True else ''}"f" {res}\n")
            sock.close()