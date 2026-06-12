import sys
import io
import os
import time
import ctypes
import threading
import queue
import logging
from datetime import datetime

# Prevent scapy from printing IPv6 warning on startup
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import (
        sniff, conf, Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, DNSRR, Raw, rdpcap, wrpcap
    )
except ImportError:
    print("Error: Scapy is not installed. Please install it using 'pip install scapy'.")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.live import Live
    from rich.layout import Layout
    from rich.tree import Tree
    from rich.prompt import Prompt, Confirm
    from rich.align import Align
    import rich.box as box
except ImportError:
    print("Error: Rich is not installed. Please install it using 'pip install rich'.")
    sys.exit(1)

# Fix Windows terminal encoding to support Unicode/emoji characters
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Initialize Rich Console
console = Console(force_terminal=True)

# Global statistics and captured packets
captured_packets = []
stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "dns": 0,
    "arp": 0,
    "http": 0,
    "other": 0
}

def reset_session():
    """Resets the statistics and packet log for a new capture session."""
    global captured_packets, stats
    captured_packets = []
    stats = {
        "total": 0,
        "tcp": 0,
        "udp": 0,
        "icmp": 0,
        "dns": 0,
        "arp": 0,
        "http": 0,
        "other": 0
    }

def is_admin():
    """Checks if the script is running with administrative privileges on Windows."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def get_packet_addresses(packet):
    """Extracts source and destination addresses from a packet."""
    src = "Unknown"
    dst = "Unknown"
    
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
    elif packet.haslayer(IPv6):
        src = packet[IPv6].src
        dst = packet[IPv6].dst
    elif packet.haslayer(ARP):
        src = packet[ARP].psrc
        dst = packet[ARP].pdst
    elif packet.haslayer(Ether):
        src = packet[Ether].src
        dst = packet[Ether].dst
        
    return src, dst

def get_packet_protocol(packet):
    """Determines the primary protocol of a packet for display and statistics."""
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(TCP):
        # Check HTTP
        tcp = packet[TCP]
        payload = bytes(tcp.payload)
        if len(payload) > 0:
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                if payload_str.startswith(("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH", "HTTP/")):
                    return "HTTP"
            except:
                pass
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(IP):
        return "IP"
    if packet.haslayer(IPv6):
        return "IPv6"
    return "Other"

def get_packet_summary(packet):
    """Generates a human-readable summary description of the packet content."""
    if packet.haslayer(ARP):
        arp = packet[ARP]
        if arp.op == 1:
            return f"Who has {arp.pdst}? Tell {arp.psrc}"
        elif arp.op == 2:
            return f"ARP Reply: {arp.hwsrc} is at {arp.psrc}"
        return f"ARP op={arp.op}"
    
    if packet.haslayer(IP) or packet.haslayer(IPv6):
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = []
            if tcp.flags.S: flags.append("SYN")
            if tcp.flags.A: flags.append("ACK")
            if tcp.flags.F: flags.append("FIN")
            if tcp.flags.R: flags.append("RST")
            if tcp.flags.P: flags.append("PSH")
            if tcp.flags.U: flags.append("URG")
            flags_desc = "+".join(flags) if flags else str(tcp.flags)
            
            # Check for HTTP payload
            payload = bytes(tcp.payload)
            if len(payload) > 0:
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')
                    if payload_str.startswith(("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH")):
                        first_line = payload_str.split("\r\n")[0]
                        return f"HTTP Request: {first_line}"
                    elif payload_str.startswith("HTTP/"):
                        first_line = payload_str.split("\r\n")[0]
                        return f"HTTP Response: {first_line}"
                except:
                    pass
            return f"TCP Port {tcp.sport} -> {tcp.dport} [{flags_desc}] Seq={tcp.seq} Ack={tcp.ack}"
            
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            if packet.haslayer(DNS):
                dns = packet[DNS]
                if dns.qr == 0:
                    qname = dns.qd.qname.decode('utf-8', errors='ignore') if dns.qd else "Unknown"
                    return f"DNS Query: {qname}"
                else:
                    answers = []
                    if dns.an:
                        for i in range(min(dns.ancount, 2)):
                            try:
                                rdata = dns.an[i].rdata
                                if isinstance(rdata, bytes):
                                    rdata = rdata.decode('utf-8', errors='ignore')
                                answers.append(str(rdata))
                            except:
                                pass
                    ans_str = ", ".join(answers) if answers else "IP Resolved"
                    return f"DNS Response: {ans_str}"
            return f"UDP Port {udp.sport} -> {udp.dport} Len={udp.len}"
            
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            types = {0: "Echo Reply (ping)", 8: "Echo Request (ping)", 3: "Destination Unreachable"}
            type_name = types.get(icmp.type, f"Type={icmp.type}")
            return f"ICMP {type_name} Code={icmp.code}"
            
    return packet.summary()

def update_stats(packet):
    """Updates global packet statistics."""
    global stats
    proto = get_packet_protocol(packet)
    stats["total"] += 1
    if proto == "TCP":
        stats["tcp"] += 1
    elif proto == "UDP":
        stats["udp"] += 1
    elif proto == "ICMP":
        stats["icmp"] += 1
    elif proto == "DNS":
        stats["dns"] += 1
        stats["udp"] += 1
    elif proto == "ARP":
        stats["arp"] += 1
    elif proto == "HTTP":
        stats["http"] += 1
        stats["tcp"] += 1
    else:
        stats["other"] += 1

def packet_matches_filter(pkt, filter_str):
    """Evaluates if a packet matches the simple display filter query."""
    if not filter_str:
        return True
    
    filter_str = filter_str.lower()
    
    # Check Protocol
    proto = get_packet_protocol(pkt).lower()
    if filter_str == proto:
        return True
    
    # Check IP or MAC address
    src, dst = get_packet_addresses(pkt)
    if filter_str in src.lower() or filter_str in dst.lower():
        return True
    
    # Check text in summary
    summary = get_packet_summary(pkt).lower()
    if filter_str in summary:
        return True
        
    return False

def make_layout(interface_name, filter_desc, status_text):
    """Creates the standard Rich screen layout for capturing packets."""
    layout = Layout()
    
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="stats", size=4),
        Layout(name="body", ratio=1),
        Layout(name="footer", size=3)
    )
    
    # Header Content
    header_text = Text.assemble(
        ("📡 ", "bold cyan"),
        ("ANTIGRAVITY PACKET SNIFFER ", "bold white"),
        ("| ", "dim"),
        (f"Interface: {interface_name} ", "bold green"),
        ("| ", "dim"),
        (f"Filter: {filter_desc or 'None'} ", "bold yellow"),
        ("| ", "dim"),
        (f"Status: {status_text}", "bold magenta")
    )
    layout["header"].update(Panel(header_text, border_style="cyan"))
    
    # Stats Content
    stats_table = Table.grid(expand=True)
    stats_table.add_column(justify="center", ratio=1)
    stats_table.add_column(justify="center", ratio=1)
    stats_table.add_column(justify="center", ratio=1)
    stats_table.add_column(justify="center", ratio=1)
    stats_table.add_column(justify="center", ratio=1)
    stats_table.add_column(justify="center", ratio=1)
    stats_table.add_column(justify="center", ratio=1)
    stats_table.add_column(justify="center", ratio=1)
    
    stats_table.add_row(
        Text(f"Total\n{stats['total']}", style="bold white"),
        Text(f"TCP\n{stats['tcp']}", style="bold green"),
        Text(f"UDP\n{stats['udp']}", style="bold cyan"),
        Text(f"DNS\n{stats['dns']}", style="bold magenta"),
        Text(f"HTTP\n{stats['http']}", style="bold orange3"),
        Text(f"ICMP\n{stats['icmp']}", style="bold yellow"),
        Text(f"ARP\n{stats['arp']}", style="bold red"),
        Text(f"Other\n{stats['other']}", style="dim")
    )
    layout["stats"].update(Panel(stats_table, title="Protocol Counters", border_style="blue"))
    
    # Footer Content
    footer_text = Text("Press Ctrl+C to stop capture and enter the Interactive Packet Analyzer", style="bold yellow italic")
    layout["footer"].update(Panel(Align(footer_text, align="center"), border_style="cyan"))
    
    return layout

def update_body_layout(layout, packets_list):
    """Updates the packet log table in the body of the layout."""
    table = Table(box=box.SIMPLE, expand=True)
    table.add_column("ID", justify="right", style="dim", width=6)
    table.add_column("Time", width=12)
    table.add_column("Source", width=25)
    table.add_column("Destination", width=25)
    table.add_column("Protocol", width=10)
    table.add_column("Length", justify="right", width=8)
    table.add_column("Summary", justify="left")
    
    # Display last 12 packets
    start_idx = max(0, len(packets_list) - 12)
    for idx, pkt in enumerate(packets_list[start_idx:]):
        pkt_id = start_idx + idx
        
        # Format Timestamp
        pkt_time = datetime.fromtimestamp(float(pkt.time)).strftime('%H:%M:%S.%f')[:-3]
        
        # Format Addresses
        src, dst = get_packet_addresses(pkt)
        
        # Protocol and color code
        proto = get_packet_protocol(pkt)
        proto_style = "bold white"
        if proto == "TCP": proto_style = "bold green"
        elif proto == "UDP": proto_style = "bold cyan"
        elif proto == "DNS": proto_style = "bold magenta"
        elif proto == "HTTP": proto_style = "bold orange3"
        elif proto == "ICMP": proto_style = "bold yellow"
        elif proto == "ARP": proto_style = "bold red"
        
        # Summary description
        summary = get_packet_summary(pkt)
        
        table.add_row(
            str(pkt_id),
            pkt_time,
            src,
            dst,
            Text(proto, style=proto_style),
            str(len(pkt)),
            summary
        )
        
    layout["body"].update(Panel(table, title="Live Packet Log (showing last 12)", border_style="green"))

def generate_sample_pcap(filepath="sample.pcap"):
    """Generates a sample pcap file programmatically containing mock network interactions."""
    console.print(f"[bold yellow]Generating simulated network traffic for {filepath}...[/bold yellow]")
    
    # Mock data
    ips = ["192.168.1.10", "192.168.1.50", "8.8.8.8"]
    macs = ["00:11:22:33:44:55", "66:77:88:99:aa:bb", "00:00:0c:07:ac:01"]
    
    packets = []
    t = time.time() - 30.0  # start 30 seconds ago
    
    # 1. ARP Request/Reply
    p1 = Ether(src=macs[0], dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, hwsrc=macs[0], psrc=ips[0], pdst=ips[1])
    p1.time = t
    p2 = Ether(src=macs[1], dst=macs[0])/ARP(op=2, hwsrc=macs[1], psrc=ips[1], hwdst=macs[0], pdst=ips[0])
    p2.time = t + 0.05
    packets.extend([p1, p2])
    t += 2.0
    
    # 2. DNS Query/Response
    sport_dns = 54321
    p3 = Ether()/IP(src=ips[0], dst=ips[2])/UDP(sport=sport_dns, dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com"))
    p3.time = t
    p4 = Ether()/IP(src=ips[2], dst=ips[0])/UDP(sport=53, dport=sport_dns)/DNS(qr=1, aa=1, qd=p3[DNS].qd, an=DNSRR(rrname="google.com", rdata="142.250.190.46"))
    p4.time = t + 0.1
    packets.extend([p3, p4])
    t += 3.0
    
    # 3. HTTP Connection (SYN -> SYN-ACK -> ACK -> GET -> Response -> FIN)
    sport_http = 61234
    dest_ip = "142.250.190.46"
    
    syn = Ether()/IP(src=ips[0], dst=dest_ip)/TCP(sport=sport_http, dport=80, flags="S", seq=100)
    syn.time = t
    syn_ack = Ether()/IP(src=dest_ip, dst=ips[0])/TCP(sport=80, dport=sport_http, flags="SA", seq=1000, ack=101)
    syn_ack.time = t + 0.08
    ack = Ether()/IP(src=ips[0], dst=dest_ip)/TCP(sport=sport_http, dport=80, flags="A", seq=101, ack=1001)
    ack.time = t + 0.09
    
    get_req = Ether()/IP(src=ips[0], dst=dest_ip)/TCP(sport=sport_http, dport=80, flags="PA", seq=101, ack=1001)/Raw(load="GET /index.html HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n")
    get_req.time = t + 0.12
    
    resp_load = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 51\r\n\r\n<html><body><h1>Welcome to Google!</h1></body></html>"
    http_resp = Ether()/IP(src=dest_ip, dst=ips[0])/TCP(sport=80, dport=sport_http, flags="PA", seq=1001, ack=101+len(get_req[Raw].load))/Raw(load=resp_load)
    http_resp.time = t + 0.22
    
    packets.extend([syn, syn_ack, ack, get_req, http_resp])
    t += 5.0
    
    # 4. ICMP Ping Request/Reply
    p_icmp_req = Ether()/IP(src=ips[0], dst=ips[1])/ICMP(type=8, code=0)
    p_icmp_req.time = t
    p_icmp_repl = Ether()/IP(src=ips[1], dst=ips[0])/ICMP(type=0, code=0)
    p_icmp_repl.time = t + 0.03
    packets.extend([p_icmp_req, p_icmp_repl])
    
    # Save packets
    try:
        wrpcap(filepath, packets)
        console.print(f"[bold green]Successfully generated {len(packets)} sample packets in {filepath}[/bold green]\n")
    except Exception as e:
        console.print(f"[bold red]Failed to write sample PCAP file: {e}[/bold red]\n")

def display_hexdump(packet):
    """Captures and returns the formatted hexdump of a packet using Scapy's hexdump utility."""
    # Custom hexdump formatting or wrap Scapy's hexdump
    from scapy.utils import hexdump
    return hexdump(packet, dump=True)

def show_packet_detail(pkt, pkt_id):
    """Displays layer-by-layer decoded tree and side-by-side hex dump for a specific packet."""
    tree = Tree(f"[bold cyan]Packet #{pkt_id} Protocol Headers[/bold cyan]")
    
    layer = pkt
    while layer:
        layer_title = f"[bold yellow]{layer.name}[/bold yellow]"
        # If transport/network layers, highlight specific ports/IPs
        if layer.name == "IP":
            layer_title += f" (IPv4: {layer.src} -> {layer.dst})"
        elif layer.name == "TCP":
            layer_title += f" (TCP Port: {layer.sport} -> {layer.dport} Flags: {layer.flags})"
        elif layer.name == "UDP":
            layer_title += f" (UDP Port: {layer.sport} -> {layer.dport})"
        elif layer.name == "DNS":
            layer_title += " (DNS Protocol)"
            
        layer_tree = tree.add(layer_title)
        
        # Display each field of the layer
        for field in layer.fields_desc:
            try:
                val = layer.getfieldval(field.name)
                # Pretty format certain field types
                if isinstance(val, bytes):
                    try:
                        val_str = val.decode('utf-8')
                        # check if it's printable ascii
                        if not all(32 <= ord(c) < 127 or c in '\r\n\t' for c in val_str):
                            val_str = val.hex()
                    except:
                        val_str = val.hex()
                elif isinstance(val, list):
                    val_str = ", ".join(str(v) for v in val)
                else:
                    val_str = str(val)
                
                layer_tree.add(f"[green]{field.name}:[/green] {val_str}")
            except Exception as e:
                layer_tree.add(f"[red]Failed to read field {field.name}: {e}[/red]")
                
        layer = layer.payload
        
    # Generate hexdump
    try:
        hd = display_hexdump(pkt)
    except Exception as e:
        hd = f"Error generating hexdump: {e}"
        
    # Display details
    console.print("\n")
    console.print(Panel(tree, title=f"Packet #{pkt_id} Structure", border_style="cyan"))
    console.print(Panel(Text(hd, style="dim green"), title=f"Packet #{pkt_id} Raw Hexdump", border_style="green"))
    console.print("\n")

def interactive_analyzer():
    """Runs the command-line packet inspection environment once sniffing has paused/completed."""
    display_filter = ""
    
    console.print(Panel(
        "[bold cyan]INTERACTIVE ANALYZER SHELL ENTERED[/bold cyan]\n"
        "All captured packets are loaded in memory. You can search, filter, and inspect them.",
        border_style="cyan"
    ))
    
    while True:
        prompt_suffix = f" [yellow](Filter: '{display_filter}')[/yellow]" if display_filter else ""
        cmd_input = Prompt.ask(f"[bold magenta]analyzer{prompt_suffix}>>[/bold magenta]").strip()
        
        if not cmd_input:
            continue
            
        parts = cmd_input.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""
        
        if cmd in ("h", "help", "?"):
            console.print(
                "[bold cyan]Available Analyzer Commands:[/bold cyan]\n"
                "  [bold green]l, list[/bold green]          : List captured packets (applies active display filter)\n"
                "  [bold green]d, detail <id>[/bold green]   : Decode and view details of packet by ID (e.g. 'detail 5')\n"
                "  [bold green]f, filter <term>[/bold green] : Filter list by protocol/IP/text (e.g. 'filter tcp', 'filter 8.8.8.8')\n"
                "  [bold green]c, clear[/bold green]          : Clear current display filter\n"
                "  [bold green]s, save <file>[/bold green]   : Save all captured packets to a PCAP file (e.g. 'save capture.pcap')\n"
                "  [bold green]r, resume[/bold green]        : Resume packet sniffing\n"
                "  [bold green]m, menu[/bold green]          : Return to main menu (clears captured packets)\n"
                "  [bold green]q, exit, quit[/bold green]    : Exit the application"
            )
            
        elif cmd in ("l", "list"):
            # Create list table
            table = Table(box=box.SIMPLE, expand=True)
            table.add_column("ID", justify="right", style="dim")
            table.add_column("Time")
            table.add_column("Source")
            table.add_column("Destination")
            table.add_column("Protocol")
            table.add_column("Length", justify="right")
            table.add_column("Summary", justify="left")
            
            matched_count = 0
            for idx, pkt in enumerate(captured_packets):
                if not packet_matches_filter(pkt, display_filter):
                    continue
                matched_count += 1
                pkt_time = datetime.fromtimestamp(float(pkt.time)).strftime('%H:%M:%S.%f')[:-3]
                src, dst = get_packet_addresses(pkt)
                proto = get_packet_protocol(pkt)
                proto_style = "bold white"
                if proto == "TCP": proto_style = "bold green"
                elif proto == "UDP": proto_style = "bold cyan"
                elif proto == "DNS": proto_style = "bold magenta"
                elif proto == "HTTP": proto_style = "bold orange3"
                elif proto == "ICMP": proto_style = "bold yellow"
                elif proto == "ARP": proto_style = "bold red"
                
                table.add_row(
                    str(idx),
                    pkt_time,
                    src,
                    dst,
                    Text(proto, style=proto_style),
                    str(len(pkt)),
                    get_packet_summary(pkt)
                )
                
            if matched_count == 0:
                console.print("[yellow]No packets match the active filter.[/yellow]")
            else:
                console.print(f"[dim]Displaying {matched_count} of {len(captured_packets)} packets:[/dim]")
                # Open with system pager for scrollable reading
                with console.pager():
                    console.print(table)
                    
        elif cmd in ("d", "detail", "inspect"):
            if not arg:
                console.print("[bold red]Error: Please specify a packet ID (e.g. 'detail 3')[/bold red]")
                continue
            try:
                pkt_id = int(arg)
                if pkt_id < 0 or pkt_id >= len(captured_packets):
                    console.print(f"[bold red]Error: Invalid packet ID. Must be between 0 and {len(captured_packets)-1}.[/bold red]")
                else:
                    show_packet_detail(captured_packets[pkt_id], pkt_id)
            except ValueError:
                console.print("[bold red]Error: Packet ID must be an integer.[/bold red]")
                
        elif cmd in ("f", "filter"):
            if not arg:
                console.print("[bold red]Error: Please specify a filter term (e.g. 'filter TCP' or 'filter 192.168.1.1')[/bold red]")
            else:
                display_filter = arg
                console.print(f"[green]Display filter set to: '{display_filter}'[/green]")
                
        elif cmd in ("c", "clear"):
            display_filter = ""
            console.print("[green]Display filter cleared.[/green]")
            
        elif cmd in ("s", "save"):
            filepath = arg if arg else "capture.pcap"
            if not filepath.endswith(".pcap"):
                filepath += ".pcap"
            try:
                wrpcap(filepath, captured_packets)
                console.print(f"[bold green]Successfully saved {len(captured_packets)} packets to {filepath}[/bold green]")
            except Exception as e:
                console.print(f"[bold red]Failed to save packets: {e}[/bold red]")
                
        elif cmd in ("r", "resume"):
            return "resume"
            
        elif cmd in ("m", "menu"):
            if Confirm.ask("[yellow]Returning to main menu will discard the current capture. Continue?[/yellow]"):
                return "menu"
                
        elif cmd in ("q", "exit", "quit"):
            if Confirm.ask("[yellow]Are you sure you want to exit the application?[/yellow]"):
                return "exit"
        else:
            console.print(f"[bold red]Unknown command: '{cmd}'. Type 'help' for available commands.[/bold red]")

def simulation_worker(pkt_queue, stop_event):
    """Thread function that produces a realistic stream of network packets."""
    ips = ["192.168.1.10", "192.168.1.45", "192.168.1.254", "8.8.8.8", "142.250.190.46"]
    macs = ["8e:30:4b:d0:0b:5e", "0a:00:27:00:00:15", "00:00:0c:07:ac:01", "8c:f8:c5:7d:4b:4c"]
    
    import random
    
    while not stop_event.is_set():
        scenario = random.choice(["arp", "dns", "http", "icmp", "tcp_noise"])
        packets = []
        t = time.time()
        
        if scenario == "arp":
            p1 = Ether(src=macs[0], dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, hwsrc=macs[0], psrc=ips[0], pdst=ips[1])
            p2 = Ether(src=macs[1], dst=macs[0])/ARP(op=2, hwsrc=macs[1], psrc=ips[1], hwdst=macs[0], pdst=ips[0])
            packets = [p1, p2]
            
        elif scenario == "dns":
            domain = random.choice(["google.com", "github.com", "python.org", "wikipedia.org"])
            sport = random.randint(49152, 65535)
            p1 = Ether()/IP(src=ips[0], dst=ips[3])/UDP(sport=sport, dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
            p2 = Ether()/IP(src=ips[3], dst=ips[0])/UDP(sport=53, dport=sport)/DNS(qr=1, aa=1, qd=p1[DNS].qd, an=DNSRR(rrname=domain, rdata="142.250.190.46"))
            packets = [p1, p2]
            
        elif scenario == "http":
            server = ips[4]
            sport = random.randint(49152, 65535)
            syn = Ether()/IP(src=ips[0], dst=server)/TCP(sport=sport, dport=80, flags="S", seq=random.randint(1000, 10000))
            syn_ack = Ether()/IP(src=server, dst=ips[0])/TCP(sport=80, dport=sport, flags="SA", seq=random.randint(20000, 30000), ack=syn[TCP].seq+1)
            ack = Ether()/IP(src=ips[0], dst=server)/TCP(sport=sport, dport=80, flags="A", seq=syn[TCP].seq+1, ack=syn_ack[TCP].seq+1)
            
            get_req = Ether()/IP(src=ips[0], dst=server)/TCP(sport=sport, dport=80, flags="PA", seq=ack[TCP].seq, ack=ack[TCP].ack)/Raw(load=f"GET /index.html HTTP/1.1\r\nHost: {server}\r\nUser-Agent: python-requests\r\n\r\n")
            
            http_resp = Ether()/IP(src=server, dst=ips[0])/TCP(sport=80, dport=sport, flags="PA", seq=syn_ack[TCP].seq+1, ack=get_req[TCP].seq+len(get_req[Raw].load))/Raw(load="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 48\r\n\r\n<html><body><h1>It Works!</h1></body></html>")
            
            packets = [syn, syn_ack, ack, get_req, http_resp]
            
        elif scenario == "icmp":
            p1 = Ether()/IP(src=ips[0], dst=ips[1])/ICMP(type=8, code=0)
            p2 = Ether()/IP(src=ips[1], dst=ips[0])/ICMP(type=0, code=0)
            packets = [p1, p2]
            
        else:
            sport = random.randint(1024, 49151)
            dport = random.randint(1024, 49151)
            p = Ether()/IP(src=ips[0], dst=ips[2])/TCP(sport=sport, dport=dport, flags="PA")/Raw(load="Custom payload packet noise")
            packets = [p]
            
        # Push packets into queue with timing delay
        for idx, pkt in enumerate(packets):
            if stop_event.is_set():
                break
            pkt.time = t + (idx * 0.05)
            pkt_queue.put(pkt)
            time.sleep(random.uniform(0.05, 0.2))
            
        # Idle between packet scenarios
        time.sleep(random.uniform(0.8, 2.5))

def run_simulation():
    """Runs the interactive GUI-like dashboard with generated traffic."""
    reset_session()
    
    stop_event = threading.Event()
    pkt_queue = queue.Queue()
    sim_thread = threading.Thread(target=simulation_worker, args=(pkt_queue, stop_event))
    sim_thread.start()
    
    layout = make_layout("Simulated Connection", "All Traffic", "Active (Simulated)")
    
    console.print("[bold yellow]Starting traffic simulation. Press Ctrl+C to stop sniffing and open the analyzer.[/bold yellow]\n")
    time.sleep(1.0)
    
    try:
        last_update = 0
        with Live(layout, refresh_per_second=10) as live:
            while not stop_event.is_set():
                try:
                    # Non-blocking fetch from queue
                    pkt = pkt_queue.get(timeout=0.1)
                    captured_packets.append(pkt)
                    update_stats(pkt)
                    
                    now = time.time()
                    if now - last_update > 0.1:
                        update_body_layout(layout, captured_packets)
                        live.update(layout)
                        last_update = now
                except queue.Empty:
                    pass
    except KeyboardInterrupt:
        # User requested stop
        pass
    finally:
        stop_event.set()
        sim_thread.join()
        
    action = interactive_analyzer()
    if action == "resume":
        run_simulation()
    return action

def run_live_sniffing():
    """Configures and runs live packet sniffing from active network interfaces."""
    # 1. Admin Privilege check
    if not is_admin():
        console.print(Panel(
            "[bold yellow]WARNING: You are not running as Administrator.[/bold yellow]\n"
            "On Windows, native raw socket packet sniffing requires Administrator privileges.\n"
            "Live capture will fail if Npcap is not installed or configured with non-admin access.\n\n"
            "To run as Administrator:\n"
            "  1. Right-click your terminal application (PowerShell / Command Prompt).\n"
            "  2. Select 'Run as administrator'.\n"
            "  3. Execute this program again.",
            title="Admin Permission Required",
            border_style="yellow"
        ))
        if not Confirm.ask("Do you want to attempt live sniffing anyway?"):
            return "menu"
            
    # 2. Get interfaces
    try:
        interfaces = list(conf.ifaces.values())
        if not interfaces:
            raise Exception("No active network interfaces detected.")
    except Exception as e:
        console.print(f"[bold red]Failed to fetch network interfaces: {e}[/bold red]")
        Prompt.ask("Press Enter to return to main menu")
        return "menu"
        
    # Display Interfaces
    table = Table(box=box.DOUBLE, title="Available Network Interfaces")
    table.add_column("Select #", justify="center")
    table.add_column("Interface Name", justify="left")
    table.add_column("MAC Address", justify="center")
    table.add_column("IPv4 Address", justify="center")
    
    for idx, iface in enumerate(interfaces):
        mac = getattr(iface, "mac", "N/A") or "N/A"
        ip = getattr(iface, "ip", "N/A") or "N/A"
        table.add_row(str(idx), iface.name, mac, ip)
        
    console.print(table)
    
    # Selection
    selection = -1
    while True:
        sel_str = Prompt.ask("Select interface number").strip()
        try:
            val = int(sel_str)
            if 0 <= val < len(interfaces):
                selection = val
                break
            else:
                console.print(f"[bold red]Please choose a number between 0 and {len(interfaces)-1}[/bold red]")
        except ValueError:
            console.print("[bold red]Please enter a valid integer[/bold red]")
            
    selected_iface = interfaces[selection]
    
    # Filter selection
    bpf_filter = Prompt.ask("Enter BPF filter (e.g. 'tcp', 'udp', 'port 80', or leave empty for all)").strip()
    
    reset_session()
    
    layout = make_layout(selected_iface.name, bpf_filter, "Active (Live)")
    console.print(f"\n[bold green]Starting live capture on {selected_iface.name}...[/bold green]")
    console.print("[bold yellow]Press Ctrl+C to stop capture and enter the Analyzer.[/bold yellow]\n")
    time.sleep(1.0)
    
    last_update = 0
    
    def packet_callback(pkt):
        nonlocal last_update
        captured_packets.append(pkt)
        update_stats(pkt)
        
        now = time.time()
        if now - last_update > 0.1:
            update_body_layout(layout, captured_packets)
            live.update(layout)
            last_update = now
            
    try:
        with Live(layout, refresh_per_second=10) as live:
            # We run Scapy's sniff. It blocks until Ctrl+C.
            # store=0 stops Scapy from caching packets internally to prevent double memory usage.
            sniff(iface=selected_iface, filter=bpf_filter, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        console.print(Panel(
            f"[bold red]Live Sniffing Error![/bold red]\n\n"
            f"Error details: {e}\n\n"
            "This usually happens on Windows if:\n"
            "  - The Npcap driver is missing (https://npcap.com/).\n"
            "  - You did not run this console as Administrator.\n\n"
            "Please try the [bold cyan]Traffic Simulation[/bold cyan] mode instead.",
            title="Capture Error",
            border_style="red"
        ))
        Prompt.ask("Press Enter to return to main menu")
        return "menu"
        
    action = interactive_analyzer()
    if action == "resume":
        # Note: Scapy doesn't allow easy resume of the exact sniff call cleanly in place without recursive nesting,
        # but we can re-enter this function or loop it. Let's run live sniffing again.
        return run_live_sniffing()
    return action

def run_pcap_reader():
    """Reads packets from an existing PCAP file and opens the Interactive Analyzer."""
    filepath = Prompt.ask("Enter path to PCAP file (e.g. 'capture.pcap')").strip()
    if not filepath:
        console.print("[bold red]Error: Filepath cannot be empty.[/bold red]")
        Prompt.ask("Press Enter to return to main menu")
        return "menu"
        
    if not os.path.exists(filepath):
        console.print(f"[bold red]Error: File '{filepath}' does not exist.[/bold red]")
        Prompt.ask("Press Enter to return to main menu")
        return "menu"
        
    console.print(f"[bold yellow]Loading packets from {filepath}...[/bold yellow]")
    reset_session()
    
    try:
        loaded = rdpcap(filepath)
        for pkt in loaded:
            captured_packets.append(pkt)
            update_stats(pkt)
        console.print(f"[bold green]Successfully loaded {len(captured_packets)} packets from {filepath}![/bold green]\n")
    except Exception as e:
        console.print(f"[bold red]Failed to parse PCAP file: {e}[/bold red]")
        Prompt.ask("Press Enter to return to main menu")
        return "menu"
        
    action = interactive_analyzer()
    return action

def main_menu():
    """Main application loop and interactive menu."""
    while True:
        console.clear()
        
        title_text = Text.assemble(
            ("📡 ", "bold cyan"),
            ("ANTIGRAVITY NETWORK SNIFFER & ANALYZER\n", "bold white"),
            ("A premium packet capture and protocol analysis tool", "dim")
        )
        
        console.print(Panel(
            Align(title_text, align="center"),
            box=box.DOUBLE,
            border_style="cyan",
            subtitle="DeepMind Advanced Agentic Coding"
        ))
        
        console.print(
            "[bold cyan]Select Operational Mode:[/bold cyan]\n"
            "  [bold green]1.[/bold green] ⚡ [bold white]Live Packet Sniffing[/bold white] (Requires Admin & Npcap)\n"
            "  [bold green]2.[/bold green] 📁 [bold white]Analyze PCAP File[/bold white] (No privileges required)\n"
            "  [bold green]3.[/bold green] 🎮 [bold white]Live Traffic Simulation[/bold white] (No privileges required)\n"
            "  [bold green]4.[/bold green] 🛠️  [bold white]Generate Sample PCAP File[/bold white]\n"
            "  [bold green]5.[/bold green] ❌ [bold white]Exit[/bold white]"
        )
        
        choice = Prompt.ask("\nChoose an option (1-5)", choices=["1", "2", "3", "4", "5"]).strip()
        
        action = "menu"
        if choice == "1":
            action = run_live_sniffing()
        elif choice == "2":
            action = run_pcap_reader()
        elif choice == "3":
            action = run_simulation()
        elif choice == "4":
            generate_sample_pcap()
            Prompt.ask("Press Enter to return to main menu")
        elif choice == "5":
            console.print("\n[bold cyan]Thank you for using Antigravity Network Sniffer. Goodbye![/bold cyan]")
            break
            
        if action == "exit":
            console.print("\n[bold cyan]Thank you for using Antigravity Network Sniffer. Goodbye![/bold cyan]")
            break

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        console.print("\n\n[bold red]Application interrupted. Exiting...[/bold red]")
        sys.exit(0)
