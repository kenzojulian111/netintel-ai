from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
from scapy.config import conf

conf.use_pcap = True
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import psutil
import socket
import subprocess
import re
import time
import platform
import os

from datetime import datetime
from collections import defaultdict
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

CAPTURE_TIME = 120
WINDOW_SIZE = 10
INTERVAL = 1
PING_INTERVAL = 5
PING_TIMEOUT = 1000
INTERFACE = None

SERVERS = {
    "Cloudflare": "1.1.1.1",
    "Google DNS": "8.8.8.8",
    "Quad9": "9.9.9.9"
}


flows = defaultdict(
    lambda: {
        "packets": 0,
        "bytes": 0,
        "first_seen": None,
        "last_seen": None
    }
)


packet_history = []

latency_history = []

interface_traffic = []

from scapy.all import get_if_list
from scapy.arch.windows import get_windows_if_list


def print_interfaces():
    interfaces = get_windows_if_list()

    print("\nNetwork interfaces:\n")

    for i, interface in enumerate(interfaces):
        name = interface.get("name", "")
        description = interface.get("description", "")
        guid = interface.get("guid", "")
        ips = interface.get("ips", [])

        print(f"[{i}] {description}")
        print(f"    Name : {name}")
        print(f"    GUID : {guid}")
        print(f"    IP   : {', '.join(ips)}")
        print()


def select_interface():

    global INTERFACE

    if INTERFACE is not None:
        return INTERFACE

    windows_interfaces = get_windows_if_list()
    npf_interfaces = get_if_list()

    if not windows_interfaces:
        print("Tidak ada network interface.")
        raise SystemExit

    print_interfaces()

    try:
        choice = int(
            input("Pilih nomor interface: ")
        )

        if choice < 0 or choice >= len(windows_interfaces):
            raise ValueError

    except ValueError:
        print("Pilihan interface tidak valid.")
        raise SystemExit

    selected = windows_interfaces[choice]

    guid = selected.get("guid", "")

    guid_clean = guid.replace(
        "{", ""
    ).replace(
        "}", ""
    ).lower()

    matched_interface = None

    for npf in npf_interfaces:

        npf_clean = npf.lower()

        if guid_clean in npf_clean:
            matched_interface = npf
            break

    if matched_interface is None:
        print("\nNPF interface tidak ditemukan.")
        print("Interface yang tersedia:")

        for interface in npf_interfaces:
            print(interface)

        raise SystemExit

    INTERFACE = matched_interface

    print("\nInterface terpilih:")
    print(
        f"Description : "
        f"{selected.get('description', '')}"
    )
    print(
        f"GUID        : "
        f"{selected.get('guid', '')}"
    )
    print(
        f"NPF         : "
        f"{INTERFACE}"
    )
    print(
        f"IP          : "
        f"{', '.join(selected.get('ips', []))}"
    )

    return INTERFACE


def get_interface_counters(
    interface
):

    counters = psutil.net_io_counters(
        pernic=True
    )

    if interface not in counters:
        return None

    return counters[interface]


def calculate_traffic_rate(
    previous,
    current,
    elapsed
):

    if (
        previous is None or
        current is None
    ):
        return 0.0, 0.0

    if elapsed <= 0:
        return 0.0, 0.0

    upload_bytes = (
        current.bytes_sent -
        previous.bytes_sent
    )

    download_bytes = (
        current.bytes_recv -
        previous.bytes_recv
    )

    upload_mbps = (
        upload_bytes * 8 /
        elapsed /
        1_000_000
    )

    download_mbps = (
        download_bytes * 8 /
        elapsed /
        1_000_000
    )

    return (
        upload_mbps,
        download_mbps
    )


def detect_protocol(
    packet
):

    if packet.haslayer(TCP):
        return "TCP"

    if packet.haslayer(UDP):
        return "UDP"

    if packet.haslayer(ICMP):
        return "ICMP"

    if packet.haslayer(IP):
        return str(
            packet[IP].proto
        )

    return "OTHER"


def process_packet(
    packet
):

    if not packet.haslayer(IP):
        return

    ip = packet[IP]

    src = ip.src
    dst = ip.dst

    protocol = detect_protocol(
        packet
    )

    packet_length = len(packet)

    source_port = None
    destination_port = None

    if packet.haslayer(TCP):

        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif packet.haslayer(UDP):

        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    key = (
        src,
        dst,
        protocol,
        source_port,
        destination_port
    )

    now = datetime.now()

    flow = flows[key]

    flow["packets"] += 1

    flow["bytes"] += packet_length

    if flow["first_seen"] is None:
        flow["first_seen"] = now

    flow["last_seen"] = now


def ping(
    host
):

    system = platform.system().lower()

    if system == "windows":

        command = [
            "ping",
            "-n",
            "1",
            "-w",
            str(PING_TIMEOUT),
            host
        ]

    else:

        command = [
            "ping",
            "-c",
            "1",
            "-W",
            "1",
            host
        ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    match = re.search(
        r"time[=<]\s*"
        r"(\d+(?:\.\d+)?)"
        r"\s*ms",
        result.stdout,
        re.IGNORECASE
    )

    if match:
        return float(
            match.group(1)
        )

    return None


def collect_latency():

    timestamp = datetime.now()

    rows = []

    for name, host in SERVERS.items():

        latency = ping(host)

        rows.append(
            {
                "timestamp": timestamp,
                "server": name,
                "host": host,
                "latency_ms": latency
            }
        )

    return rows


def create_flow_dataframe():

    rows = []

    for key, data in flows.items():

        (
            src,
            dst,
            protocol,
            source_port,
            destination_port
        ) = key

        duration = (
            data["last_seen"] -
            data["first_seen"]
        ).total_seconds()

        if duration <= 0:
            duration = 1

        bytes_per_second = (
            data["bytes"] /
            duration
        )

        mbps = (
            bytes_per_second *
            8 /
            1_000_000
        )

        rows.append(
            {
                "Source": src,
                "Destination": dst,
                "Protocol": protocol,
                "Source Port": source_port,
                "Destination Port": destination_port,
                "Packets": data["packets"],
                "Bytes": data["bytes"],
                "Duration": duration,
                "Mbps": mbps,
                "First Seen": data["first_seen"],
                "Last Seen": data["last_seen"]
            }
        )

    if not rows:
        return pd.DataFrame()

    return pd.DataFrame(rows)


def create_latency_summary(
    latency_df
):

    results = []

    for server in SERVERS:

        data = latency_df[
            latency_df["server"] == server
        ]

        if data.empty:
            continue

        successful = (
            data["latency_ms"]
            .dropna()
        )

        total = len(data)

        received = len(successful)

        lost = (
            total -
            received
        )

        loss = (
            lost /
            total *
            100
        )

        if received > 0:

            avg = successful.mean()

            minimum = successful.min()

            maximum = successful.max()

            median = successful.median()

        else:

            avg = np.nan
            minimum = np.nan
            maximum = np.nan
            median = np.nan

        if received >= 2:

            jitter = (
                successful
                .diff()
                .abs()
                .dropna()
                .mean()
            )

        else:

            jitter = np.nan

        results.append(
            {
                "Server": server,
                "Sent": total,
                "Received": received,
                "Lost": lost,
                "Packet Loss %": loss,
                "Average RTT ms": avg,
                "Median RTT ms": median,
                "Min RTT ms": minimum,
                "Max RTT ms": maximum,
                "Jitter ms": jitter
            }
        )

    return pd.DataFrame(
        results
    )


def train_ai(
    flow_df
):

    if flow_df.empty:
        return flow_df

    if len(flow_df) < 10:

        flow_df["AI Score"] = np.nan

        flow_df["Status"] = (
            "INSUFFICIENT DATA"
        )

        return flow_df

    feature_columns = [
        "Packets",
        "Bytes",
        "Duration",
        "Mbps"
    ]

    X = flow_df[
        feature_columns
    ].replace(
        [np.inf, -np.inf],
        np.nan
    ).fillna(0)

    scaler = StandardScaler()

    X_scaled = scaler.fit_transform(
        X
    )

    model = IsolationForest(
        n_estimators=300,
        contamination=0.05,
        random_state=42
    )

    model.fit(
        X_scaled
    )

    prediction = model.predict(
        X_scaled
    )

    score = model.decision_function(
        X_scaled
    )

    flow_df["AI Score"] = score

    flow_df["Status"] = np.where(
        prediction == -1,
        "ANOMALY",
        "NORMAL"
    )

    return flow_df


def create_destination_summary(
    flow_df
):

    if flow_df.empty:
        return pd.DataFrame()

    result = (
        flow_df
        .groupby(
            "Destination"
        )
        .agg(
            Packets=(
                "Packets",
                "sum"
            ),
            Bytes=(
                "Bytes",
                "sum"
            ),
            Mbps=(
                "Mbps",
                "sum"
            ),
            Flows=(
                "Destination",
                "count"
            )
        )
        .sort_values(
            "Bytes",
            ascending=False
        )
    )

    return result


def create_protocol_summary(
    flow_df
):

    if flow_df.empty:
        return pd.DataFrame()

    result = (
        flow_df
        .groupby(
            "Protocol"
        )
        .agg(
            Packets=(
                "Packets",
                "sum"
            ),
            Bytes=(
                "Bytes",
                "sum"
            ),
            Mbps=(
                "Mbps",
                "sum"
            ),
            Flows=(
                "Protocol",
                "count"
            )
        )
        .sort_values(
            "Bytes",
            ascending=False
        )
    )

    return result


def create_ai_destination_ranking(
    flow_df
):

    if flow_df.empty:
        return pd.DataFrame()

    result = (
        flow_df
        .groupby(
            "Destination"
        )
        .agg(
            Total_Bytes=(
                "Bytes",
                "sum"
            ),
            Total_Packets=(
                "Packets",
                "sum"
            ),
            Total_Mbps=(
                "Mbps",
                "sum"
            ),
            Average_AI_Score=(
                "AI Score",
                "mean"
            ),
            Anomalies=(
                "Status",
                lambda x:
                (x == "ANOMALY").sum()
            )
        )
    )

    result[
        "Traffic Share %"
    ] = (
        result["Total_Bytes"] /
        result["Total_Bytes"].sum() *
        100
    )

    result = result.sort_values(
        "Total_Bytes",
        ascending=False
    )

    return result


def create_excel(
    flow_df,
    latency_df,
    latency_summary,
    destination_summary,
    protocol_summary,
    ai_ranking,
    interface_summary,
    timestamp
):

    filename = (
        f"network_ai_report_"
        f"{timestamp}.xlsx"
    )

    anomalies = flow_df[
        flow_df["Status"] ==
        "ANOMALY"
    ].copy()

    with pd.ExcelWriter(
        filename,
        engine="openpyxl"
    ) as writer:

        flow_df.to_excel(
            writer,
            sheet_name="Flows",
            index=False
        )

        latency_df.to_excel(
            writer,
            sheet_name="Latency",
            index=False
        )

        latency_summary.to_excel(
            writer,
            sheet_name="Latency Summary",
            index=False
        )

        destination_summary.to_excel(
            writer,
            sheet_name="Destinations"
        )

        protocol_summary.to_excel(
            writer,
            sheet_name="Protocols"
        )

        ai_ranking.to_excel(
            writer,
            sheet_name="AI Ranking"
        )

        anomalies.to_excel(
            writer,
            sheet_name="AI Anomalies",
            index=False
        )

        interface_summary.to_excel(
            writer,
            sheet_name="Bandwidth",
            index=False
        )

    return filename


def create_plots(
    flow_df,
    latency_df,
    destination_summary,
    protocol_summary,
    interface_summary
):

    plt.figure(
        figsize=(14, 6)
    )

    if not latency_df.empty:

        for server in SERVERS:

            data = latency_df[
                latency_df["server"] ==
                server
            ]

            plt.plot(
                data["timestamp"],
                data["latency_ms"],
                label=server
            )

    plt.title(
        "Network RTT"
    )

    plt.xlabel(
        "Time"
    )

    plt.ylabel(
        "Latency ms"
    )

    plt.grid(True)

    plt.legend()

    plt.xticks(
        rotation=45
    )

    plt.tight_layout()


    plt.figure(
        figsize=(14, 6)
    )

    if not latency_df.empty:

        for server in SERVERS:

            data = latency_df[
                latency_df["server"] ==
                server
            ].copy()

            data["jitter"] = (
                data["latency_ms"]
                .diff()
                .abs()
            )

            plt.plot(
                data["timestamp"],
                data["jitter"],
                label=server
            )

    plt.title(
        "Network Jitter"
    )

    plt.xlabel(
        "Time"
    )

    plt.ylabel(
        "Jitter ms"
    )

    plt.grid(True)

    plt.legend()

    plt.xticks(
        rotation=45
    )

    plt.tight_layout()


    plt.figure(
        figsize=(14, 6)
    )

    if not latency_df.empty:

        for server in SERVERS:

            data = latency_df[
                latency_df["server"] ==
                server
            ].copy()

            data["loss"] = (
                data["latency_ms"]
                .isna()
                .astype(int)
            )

            plt.plot(
                data["timestamp"],
                data["loss"],
                label=server
            )

    plt.title(
        "Packet Loss Events"
    )

    plt.xlabel(
        "Time"
    )

    plt.ylabel(
        "Lost Packet"
    )

    plt.grid(True)

    plt.legend()

    plt.xticks(
        rotation=45
    )

    plt.tight_layout()


    if not destination_summary.empty:

        plt.figure(
            figsize=(14, 6)
        )

        top = (
            destination_summary
            .head(10)
        )

        plt.bar(
            top.index.astype(str),
            top["Mbps"]
        )

        plt.title(
            "Top Network Destinations"
        )

        plt.xlabel(
            "Destination"
        )

        plt.ylabel(
            "Mbps"
        )

        plt.xticks(
            rotation=45,
            ha="right"
        )

        plt.tight_layout()


    if not protocol_summary.empty:

        plt.figure(
            figsize=(12, 6)
        )

        plt.bar(
            protocol_summary.index,
            protocol_summary["Bytes"]
        )

        plt.title(
            "Traffic by Protocol"
        )

        plt.xlabel(
            "Protocol"
        )

        plt.ylabel(
            "Bytes"
        )

        plt.tight_layout()


    if not interface_summary.empty:

        plt.figure(
            figsize=(14, 6)
        )

        plt.plot(
            interface_summary[
                "timestamp"
            ],
            interface_summary[
                "download_mbps"
            ],
            label="Download"
        )

        plt.plot(
            interface_summary[
                "timestamp"
            ],
            interface_summary[
                "upload_mbps"
            ],
            label="Upload"
        )

        plt.title(
            "Interface Traffic Rate"
        )

        plt.xlabel(
            "Time"
        )

        plt.ylabel(
            "Mbps"
        )

        plt.grid(True)

        plt.legend()

        plt.xticks(
            rotation=45
        )

        plt.tight_layout()


def main():

    interface = select_interface()

    print(
        f"\nCapturing traffic for "
        f"{CAPTURE_TIME} seconds..."
    )

    previous_counter = (
        get_interface_counters(
            interface
        )
    )

    traffic_start = (
        datetime.now()
    )

    def traffic_monitor():

        nonlocal previous_counter

        start = time.time()

        while (
            time.time() -
            start
        ) < CAPTURE_TIME:

            time.sleep(
                INTERVAL
            )

            current = (
                get_interface_counters(
                    interface
                )
            )

            elapsed = (
                time.time() -
                start
            )

            upload, download = (
                calculate_traffic_rate(
                    previous_counter,
                    current,
                    INTERVAL
                )
            )

            timestamp = datetime.now()

            interface_traffic.append(
                {
                    "timestamp": timestamp,
                    "interface": interface,
                    "upload_mbps": upload,
                    "download_mbps": download
                }
            )

            previous_counter = current

    import threading

    traffic_thread = threading.Thread(
        target=traffic_monitor,
        daemon=True
    )

    traffic_thread.start()

    latency_start = time.time()

    def latency_monitor():

        while (
            time.time() -
            latency_start
        ) < CAPTURE_TIME:

            rows = collect_latency()

            latency_history.extend(
                rows
            )

            time.sleep(
                PING_INTERVAL
            )

    latency_thread = threading.Thread(
        target=latency_monitor,
        daemon=True
    )

    latency_thread.start()

    sniff(
        iface=interface,
        prn=process_packet,
        store=False,
        timeout=CAPTURE_TIME
    )

    traffic_thread.join()

    latency_thread.join()

    flow_df = (
        create_flow_dataframe()
    )

    latency_df = pd.DataFrame(
        latency_history
    )

    interface_df = pd.DataFrame(
        interface_traffic
    )

    flow_df = train_ai(
        flow_df
    )

    latency_summary = (
        create_latency_summary(
            latency_df
        )
    )

    destination_summary = (
        create_destination_summary(
            flow_df
        )
    )

    protocol_summary = (
        create_protocol_summary(
            flow_df
        )
    )

    ai_ranking = (
        create_ai_destination_ranking(
            flow_df
        )
    )

    if interface_df.empty:

        interface_summary = (
            pd.DataFrame(
                columns=[
                    "timestamp",
                    "interface",
                    "upload_mbps",
                    "download_mbps"
                ]
            )
        )

    else:

        interface_summary = (
            interface_df.copy()
        )

    timestamp = (
        datetime.now()
        .strftime(
            "%Y%m%d_%H%M%S"
        )
    )

    csv_file = (
        f"network_flows_"
        f"{timestamp}.csv"
    )

    flow_df.to_csv(
        csv_file,
        index=False
    )

    excel_file = create_excel(
        flow_df,
        latency_df,
        latency_summary,
        destination_summary,
        protocol_summary,
        ai_ranking,
        interface_summary,
        timestamp
    )

    print(
        "\nNetwork capture selesai."
    )

    print(
        f"\nInterface:"
        f"\n{interface}"
    )

    print(
        f"\nTotal flows:"
        f"\n{len(flow_df)}"
    )

    print(
        f"\nTotal packets:"
        f"\n{flow_df['Packets'].sum()}"
    )

    print(
        f"\nTotal bytes:"
        f"\n{flow_df['Bytes'].sum()}"
    )

    if not destination_summary.empty:

        print(
            "\nTop destinations:"
        )

        print(
            destination_summary
            .head(10)
            .to_string()
        )

    if not ai_ranking.empty:

        print(
            "\nAI destination ranking:"
        )

        print(
            ai_ranking
            .head(10)
            .to_string()
        )

    anomalies = flow_df[
        flow_df["Status"] ==
        "ANOMALY"
    ]

    print(
        f"\nAI anomalies:"
        f"\n{len(anomalies)}"
    )

    print(
        f"\nExcel:"
        f"\n{excel_file}"
    )

    print(
        f"\nCSV:"
        f"\n{csv_file}"
    )
    create_plots(
        flow_df,
        latency_df,
        destination_summary,
        protocol_summary,
        interface_summary
    )
    plt.show()
if __name__ == "__main__":
    main()