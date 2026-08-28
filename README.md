# NetIntel AI v2

Network telemetry, packet/flow feature engineering, ML anomaly detection, persistent storage, Excel reporting, alerts, and a Streamlit dashboard.

## Architecture

Network Interface
→ Scapy packet capture
→ time-window feature extraction
→ entropy + flow/port features
→ Isolation Forest + LOF + One-Class SVM
→ ensemble anomaly decision
→ SQLite
→ Excel / dashboard / alerts

## Features

- Cross-platform interface discovery through psutil
- Scapy packet capture
- Time-window flow statistics
- Packets/sec and bytes/sec
- Unique destination ports
- Max unique destination ports per source
- Unique flows
- TCP SYN/RST/FIN counts
- Source/destination IP entropy
- Source/destination port entropy
- Actual interface traffic rate
- RTT monitoring for configured servers
- Isolation Forest, LOF, and One-Class SVM
- Ensemble voting
- Heuristic behavior categories
- SQLite history
- Excel export
- Console + Windows beep alerts
- Optional labeled-dataset evaluation
- Unit tests
- Streamlit dashboard

## Windows prerequisites

Install Npcap from the official Npcap site. For applications using the WinPcap API, enable WinPcap API-compatible mode during installation.

Run the packet capture process with the privileges required by the selected interface.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

For Windows, also install Npcap.

## Run

```powershell
python main.py
```

Or specify the interface:

```powershell
python main.py --interface "Wi-Fi"
```

Short test:

```powershell
python main.py --baseline 3 --monitor 6 --window 5
```

## Dashboard

Run the collector first:

```powershell
python main.py
```

Then in another terminal:

```powershell
streamlit run dashboard.py
```

## Labeled dataset evaluation

A CSV can be evaluated when it contains the same feature columns as the telemetry feature set and a `label` column:

- `1` = normal
- `-1` = anomaly

Example:

```powershell
python evaluate.py dataset.csv
```

The validation reports accuracy, precision, recall, F1, and ROC-AUC for the available unsupervised models.

## Output

- `data/network.db`
- `exports/network_ai_YYYYMMDD_HHMMSS.xlsx`

The SQLite database is the long-term store. Excel is the reporting/export layer.

## Important scope

Packet capture from a laptop observes traffic visible at that laptop's network interface. It does not automatically represent every device on a Wi-Fi network. For whole-network visibility, place the sensor at the gateway, mirrored/SPAN port, or another observation point carrying the relevant traffic.

Behavior labels such as `volumetric`, `scanning`, and `syn_flood_like` are heuristic classifications unless validated against a labeled dataset.
