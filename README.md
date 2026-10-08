# Cyber Fraud Money-Mule Tracing System

An **offline** investigation tool that helps analysts follow suspected fraud proceeds through layers of mule accounts, score how suspicious each account looks, and generate print-ready case diaries and bank freeze-notice drafts, all from a single transactions CSV.

Built as a hackathon project (VoidHacks 8) and designed to handle datasets of around **2 million transactions**.

> **Disclaimer:** This is a prototype for education and demonstration. Its output is a set of rule-based indicators, not evidence or proof of wrongdoing. The generated legal notice text is a template and has not been reviewed by any legal authority. Do not use it for real enforcement actions without proper review.

---

## Features

| Module | What it does |
|---|---|
| **Dataset Loader** | Ingests a CSV (by file path or upload) with live stage-by-stage progress and a dataset fingerprint: row count, distinct accounts, date range, duplicate IDs, 99th-percentile amount and SHA-256. |
| **Search** | Look up any Account ID or Transaction ID. Shows totals in/out, counterparties, activity window, risk score, red flags and the 500 most recent transactions. Suggests close matches when nothing is found. |
| **Money Trace** | Starting from a victim account (or transaction), follows funds up to 4 hops through mule accounts and renders an interactive graph. |
| **Time Replay** | Play/pause slider that replays the flow of money over time. |
| **Risk Scoring** | Explainable 0-100 score per account; each red flag lists its points and the reason it fired. |
| **Case Report** | Printable case diary plus one bank-wise freeze-notice draft per bank, ready to save as PDF. |

---

## How it works

### Tech stack
- **Backend:** Python, [Flask](https://flask.palletsprojects.com/)
- **Database:** [DuckDB](https://duckdb.org/) (in-memory, indexed on sender, receiver and transaction ID)
- **Frontend:** Single-page `index.html` with vanilla JavaScript and SVG graph rendering, with no external CDN, so it runs fully offline

### Ingestion pipeline
1. **Uploading:** validates the file and computes its SHA-256.
2. **Reading & normalizing:** loads the CSV, matches column names case-insensitively, casts `Amount` and `Timestamp`.
3. **Indexing:** builds indexes on `Sender_Account`, `Receiver_Account` and `Transaction_ID`.
4. **Fingerprinting:** row count, distinct accounts, date range, duplicate IDs and p99 amount.

Ingestion runs in a background thread; the UI polls `/api/status` for live progress.

### Money-trace algorithm
1. **Hop 0 (victim):** every outgoing transfer from the victim account is treated as siphoned money.
2. **Hops 1-4 (mules):** for each receiving account, look at its outgoing transfers within **30 minutes** of its first incoming trace transaction. If it forwarded **at least 85%** of what it received, it is treated as a pass-through mule and the trace continues from its receivers.
3. **Round trips:** transfers back to an account already on the path are flagged `is_round_trip` and not expanded again, which prevents loops.
4. **Cash-out detection:** a node is flagged if any of its transactions use a high-risk IP prefix, a suspicious device type or a cash-out narration keyword (configurable).
5. **Summary:** amount sent by the victim, amount reaching cash-out nodes, and amount still held.

The trace stops at 4 hops or 500 nodes.

### Risk-scoring red flags

| Flag | Points | Triggers when |
|---|---:|---|
| `FAST_PASSTHROUGH` | 25 | At least 90% of received funds are forwarded within 15 minutes |
| `CASHOUT_MARKERS` | 20 | High-risk IP / suspicious device / cash-out narration seen |
| `FAN_OUT` | 15 | Sends to 3 or more distinct accounts |
| `FAN_IN` | 15 | Receives from 5 or more distinct senders |
| `ROUND_TRIP` | 10 | Funds circle back between the same accounts |
| `LARGE_AMOUNT` | 10 | A transaction exceeds the dataset's 99th percentile |
| `ODD_HOURS` | 5 | Incoming transactions between 00:00 and 05:00 |

**Risk bands:** Low (0-24), Medium (25-49), High (50-74), Critical (75-100)

---

## Project structure

```
.
├── app.py                  # Flask app: ingestion, search, trace, risk scoring, report
├── templates/
│   └── index.html          # Single-page UI (Flask serves it from templates/)
├── test_search_speed.py    # Benchmark: account search queries on DuckDB
├── test_trace_algo.py      # Benchmark / sanity check for the trace algorithm
├── .gitignore
└── README.md
```

`uploads/` is created automatically at runtime for browser-uploaded CSVs and should **not** be committed.

---

## Getting started

### Prerequisites
- Python 3.9+
- A transactions CSV in the format below (**no dataset is included in this repository**)

### Install and run

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install flask duckdb
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

### Usage
1. **Load Dataset:** enter the path to your CSV (or choose a file) and click **Load Dataset**.
2. **Search:** enter an Account ID or Transaction ID.
3. **Trace:** enter a victim Account ID or Transaction ID and click **Trace Money Flow**. Click nodes to inspect them; use the slider to replay the flow.
4. **Case Report:** open the report, then use **Print Report / Save PDF**.

---

## Expected CSV format

Header row required; column names are matched case-insensitively.

| Column | Description |
|---|---|
| `Transaction_ID` | Unique transaction identifier |
| `Sender_Account` | Sending account number |
| `Receiver_Account` | Receiving account number |
| `Sender_IFSC` | Sender's bank IFSC code |
| `Receiver_IFSC` | Receiver's bank IFSC code |
| `Amount` | Transaction amount |
| `Timestamp` | Transaction date and time |
| `Payment_Mode` | e.g. UPI, IMPS, NEFT |
| `Narration` | Free-text description |
| `IP_Address` | Originating IP |
| `Device_Type` | Originating device |

Missing columns produce a clear error on the loader screen.

---

## API reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Web UI |
| `POST` | `/api/load` | Start ingestion. JSON `{"file_path": "..."}` or multipart `file` upload |
| `GET` | `/api/status` | Live ingestion state, stage timings, summary |
| `POST` | `/api/reset` | Drop the loaded dataset |
| `GET` | `/api/dataset_info` | Loaded dataset name, row count, load time, SHA-256 |
| `GET` | `/api/search?query=` | Account or transaction lookup with stats and risk score |
| `GET` | `/api/risk_score?account_id=` | Risk score and flags for one account |
| `GET` | `/api/trace?query=` | Multi-hop money trace (nodes, edges, summary) |
| `GET` | `/report?victim=` | Printable case diary and freeze-notice drafts |

---

## Configuration

All thresholds live in the `CFG` dictionary at the top of `app.py`:

```python
CFG = {
    'FAST_PASSTHROUGH_PCT': 0.90,
    'FAST_PASSTHROUGH_MINUTES': 15,
    'FAN_OUT_MIN_ACCOUNTS': 3,
    'FAN_IN_MIN_SENDERS': 5,
    'TRACE_TIME_WINDOW_MINUTES': 30,
    'TRACE_FORWARD_PCT': 0.85,
    'TRACE_MAX_HOPS': 4,
    'TRACE_MAX_NODES': 500,
    'NIGHT_START_HOUR': 0,
    'NIGHT_END_HOUR': 5,
    'CASHOUT_IP_PREFIXES': ('185.', '194.'),
    'CASHOUT_DEVICES': ('Web_Emulator', 'Linux_Script'),
    'CASHOUT_NARRATIONS': ('WALLET', 'CRYPTO', 'P2P'),
    'RED_FLAG_WEIGHTS': { ... }
}
```

The freeze-notice wording is the editable `LEGAL_SECTION_TEXT` constant, and bank names are resolved from the IFSC prefix via `BANK_NAMES`.

---

## Benchmarks

Two standalone scripts load a large CSV into DuckDB and time the core operations:

```bash
python test_search_speed.py   # account search: stats + latest 500 transactions
python test_trace_algo.py     # runs the trace on 5 sample victims and prints timings
```

Set the `csv_path` variable at the top of each script to your own dataset location before running.

---

## Data privacy and security

Transaction data is sensitive. Please keep the following in mind:

- **Never commit datasets.** Real or realistic financial data (account numbers, IPs, narrations) must stay out of version control. The provided `.gitignore` excludes CSVs and the `uploads/` folder.
- **Run locally only.** This tool has **no authentication or access control**. Run it on `127.0.0.1` and do not expose it to the internet or an untrusted network. If you change `app.run(host=...)`, understand that anyone who can reach the port can read the loaded data.
- **Server-side file paths:** the loader accepts a file path that the server will read. This is fine for a local single-user tool but unsafe on a shared or public host.
- **Uploaded filenames** are saved as given; sanitise them (e.g. with `werkzeug.utils.secure_filename`) before any multi-user deployment.
- **Prototype only:** not hardened for production use.

---

## Limitations

- One dataset and one user at a time (a single in-memory DuckDB connection behind a lock).
- Detection is heuristic: thresholds may produce false positives and false negatives and should be tuned for your data.
- Generated notices are drafts and need review by qualified legal and investigative personnel.

---

## Contributing

Issues and pull requests are welcome. Please do not include any real financial data or personal information in issues, screenshots or commits.

## License

This project is owned by **Team Lord of the Rings**. All rights reserved.
