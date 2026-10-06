import os
import time
import hashlib
import threading
from flask import Flask, render_template, request, jsonify, make_response
import duckdb

# ==============================================================================
# CONFIGURATION & THRESHOLDS (All configuration lives here)
# ==============================================================================
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
    'RED_FLAG_WEIGHTS': {
        'FAST_PASSTHROUGH': 25,
        'CASHOUT_MARKERS': 20,
        'FAN_OUT': 15,
        'FAN_IN': 15,
        'ROUND_TRIP': 10,
        'LARGE_AMOUNT': 10,
        'ODD_HOURS': 5
    }
}

# Legal Notice Template Text (Editable constant for mentor verification)
LEGAL_SECTION_TEXT = """Notice issued under Section 94 of Bharatiya Nagarik Suraksha Sanhita (BNSS), 2023 / Section 91 of Code of Criminal Procedure (CrPC). You are hereby directed to immediately freeze the beneficiary account(s) listed below and debit-freeze all funds originating from the disputed cyber-fraud transaction(s). Please submit a compliance report along with certified account statements and KYC records to the Cyber Crime Investigation Unit within 24 hours of receipt of this notice."""

BANK_NAMES = {
    'KKBK': 'Kotak Mahindra Bank',
    'ICIC': 'ICICI Bank',
    'PYTM': 'Paytm Payments Bank',
    'HDFC': 'HDFC Bank',
    'AIRP': 'Airtel Payments Bank',
    'SBIN': 'State Bank of India',
    'UTIB': 'Axis Bank',
    'PUNB': 'Punjab National Bank',
    'BARB': 'Bank of Baroda',
    'CNRB': 'Canara Bank',
    'BKID': 'Bank of India',
    'UBIN': 'Union Bank of India',
    'IDFB': 'IDFC FIRST Bank',
    'INDB': 'IndusInd Bank',
    'YESB': 'Yes Bank',
    'IPOS': 'India Post Payments Bank'
}

app = Flask(__name__)

# Global Database Connection & Thread Lock
db = duckdb.connect()
db_lock = threading.Lock()

# Global State for Loader & Dataset Info
INGEST_STATE = {
    'status': 'idle',  # 'idle', 'loading', 'completed', 'error'
    'current_stage': None,
    'stage_times': {},
    'elapsed_sec': 0.0,
    'summary': None,
    'error_message': None,
    'loaded': False,
    'p99_amount': 0.0
}


def reset_ingest_state():
    global INGEST_STATE
    INGEST_STATE = {
        'status': 'idle',
        'current_stage': None,
        'stage_times': {},
        'elapsed_sec': 0.0,
        'summary': None,
        'error_message': None,
        'loaded': False,
        'p99_amount': 0.0
    }
    with db_lock:
        try:
            db.execute("DROP TABLE IF EXISTS transactions")
        except Exception:
            pass


def is_cashout_match(ip, device, narration):
    if ip and any(ip.startswith(prefix) for prefix in CFG['CASHOUT_IP_PREFIXES']):
        return True
    if device in CFG['CASHOUT_DEVICES']:
        return True
    if narration:
        upper_nar = narration.upper()
        if any(marker in upper_nar for marker in CFG['CASHOUT_NARRATIONS']):
            return True
    return False


# Risk Scoring Function
def compute_account_risk_score(acc_id, round_trip_accs=None):
    if not INGEST_STATE['loaded']:
        return {'risk_score': 0, 'risk_band': 'Low', 'flags': []}
        
    p99_amt = INGEST_STATE['p99_amount']
    weights = CFG['RED_FLAG_WEIGHTS']
    
    inc_txns = db.execute("""
        SELECT Transaction_ID, Sender_Account, Amount, Timestamp, Payment_Mode, Narration, IP_Address, Device_Type
        FROM transactions
        WHERE Receiver_Account = ?
        ORDER BY Timestamp ASC
    """, [acc_id]).fetchall()
    
    out_txns = db.execute("""
        SELECT Transaction_ID, Receiver_Account, Amount, Timestamp, Payment_Mode, Narration, IP_Address, Device_Type
        FROM transactions
        WHERE Sender_Account = ?
        ORDER BY Timestamp ASC
    """, [acc_id]).fetchall()
    
    total_inc = sum(r[2] for r in inc_txns)
    total_out = sum(r[2] for r in out_txns)
    
    distinct_senders = len(set(r[1] for r in inc_txns))
    distinct_receivers = len(set(r[1] for r in out_txns))
    
    flags = []
    score = 0
    
    # 1. FAST_PASSTHROUGH
    if inc_txns and out_txns:
        earliest_inc = inc_txns[0][3]
        out_15m = db.execute("""
            SELECT COALESCE(SUM(Amount), 0)
            FROM transactions
            WHERE Sender_Account = ?
              AND Timestamp >= TRY_CAST(? AS TIMESTAMP)
              AND Timestamp <= TRY_CAST(? AS TIMESTAMP) + INTERVAL '15 minutes'
        """, [acc_id, str(earliest_inc), str(earliest_inc)]).fetchone()[0]
        
        if total_inc > 0:
            fwd_pct = (out_15m / total_inc) * 100
            if fwd_pct >= (CFG['FAST_PASSTHROUGH_PCT'] * 100):
                pts = weights['FAST_PASSTHROUGH']
                score += pts
                flags.append({
                    'code': 'FAST_PASSTHROUGH',
                    'points': pts,
                    'reason': f"Forwarded {fwd_pct:.1f}% (₹{out_15m:,.2f} of ₹{total_inc:,.2f}) within 15 minutes of receipt."
                })
                
    # 2. FAN_OUT
    if distinct_receivers >= CFG['FAN_OUT_MIN_ACCOUNTS']:
        pts = weights['FAN_OUT']
        score += pts
        flags.append({
            'code': 'FAN_OUT',
            'points': pts,
            'reason': f"Distributed funds to {distinct_receivers} distinct downstream accounts."
        })
        
    # 3. FAN_IN
    if distinct_senders >= CFG['FAN_IN_MIN_SENDERS']:
        pts = weights['FAN_IN']
        score += pts
        flags.append({
            'code': 'FAN_IN',
            'points': pts,
            'reason': f"Received deposits from {distinct_senders} distinct incoming senders."
        })
        
    # 4. CASHOUT_MARKERS
    cashout_reasons = []
    all_txns = inc_txns + out_txns
    for t in all_txns:
        ip, dev, narr = t[6], t[7], t[5]
        if ip and any(ip.startswith(prefix) for prefix in CFG['CASHOUT_IP_PREFIXES']):
            cashout_reasons.append(f"High-risk IP ({ip})")
        if dev in CFG['CASHOUT_DEVICES']:
            cashout_reasons.append(f"Suspicious device ({dev})")
        if narr:
            upper_n = narr.upper()
            if any(marker in upper_n for marker in CFG['CASHOUT_NARRATIONS']):
                cashout_reasons.append(f"Cashout narration ({narr})")
                
    if cashout_reasons:
        unique_reasons = list(set(cashout_reasons))[:3]
        pts = weights['CASHOUT_MARKERS']
        score += pts
        flags.append({
            'code': 'CASHOUT_MARKERS',
            'points': pts,
            'reason': f"Triggered cashout markers: {', '.join(unique_reasons)}."
        })
        
    # 5. LARGE_AMOUNT
    max_txn_amt = max(([r[2] for r in all_txns] + [0.0]))
    if max_txn_amt > p99_amt and p99_amt > 0:
        pts = weights['LARGE_AMOUNT']
        score += pts
        flags.append({
            'code': 'LARGE_AMOUNT',
            'points': pts,
            'reason': f"Handled high-value transaction of ₹{max_txn_amt:,.2f} exceeding the dataset 99th percentile (₹{p99_amt:,.2f})."
        })
        
    # 6. ODD_HOURS
    odd_hour_count = 0
    odd_hour_sample = ""
    for t in inc_txns:
        ts = t[3]
        if ts and (CFG['NIGHT_START_HOUR'] <= ts.hour < CFG['NIGHT_END_HOUR']):
            odd_hour_count += 1
            odd_hour_sample = str(ts)
            
    if odd_hour_count > 0:
        pts = weights['ODD_HOURS']
        score += pts
        flags.append({
            'code': 'ODD_HOURS',
            'points': pts,
            'reason': f"Received {odd_hour_count} transaction(s) during odd night hours (00:00–05:00), e.g. at {odd_hour_sample}."
        })
        
    # 7. ROUND_TRIP
    senders_set = set(r[1] for r in inc_txns)
    receivers_set = set(r[1] for r in out_txns)
    overlap = senders_set.intersection(receivers_set)
    if round_trip_accs:
        overlap.update(round_trip_accs)
        
    if overlap:
        pts = weights['ROUND_TRIP']
        score += pts
        flags.append({
            'code': 'ROUND_TRIP',
            'points': pts,
            'reason': f"Involved in circular fund routing with account(s): {', '.join(list(overlap)[:2])}."
        })
        
    score = min(100, score)
    
    if score >= 75:
        band = 'Critical'
    elif score >= 50:
        band = 'High'
    elif score >= 25:
        band = 'Medium'
    else:
        band = 'Low'
        
    return {
        'account_id': acc_id,
        'risk_score': score,
        'risk_band': band,
        'flags': flags
    }


def process_csv_ingestion(file_path):
    global INGEST_STATE
    start_total_time = time.time()
    
    INGEST_STATE['status'] = 'loading'
    INGEST_STATE['error_message'] = None
    INGEST_STATE['summary'] = None
    INGEST_STATE['stage_times'] = {}
    
    try:
        # --- STAGE: Uploading / Validation ---
        INGEST_STATE['current_stage'] = 'Uploading'
        t0 = time.time()
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        h = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(4 * 1024 * 1024):
                h.update(chunk)
        file_sha256 = h.hexdigest()
        
        t_upload = time.time() - t0
        INGEST_STATE['stage_times']['Uploading'] = round(t_upload, 3)
        
        # --- STAGE: Reading & normalizing ---
        INGEST_STATE['current_stage'] = 'Reading & normalizing'
        t1 = time.time()
        
        with db_lock:
            db.execute("DROP TABLE IF EXISTS transactions")
            
            escaped_path = file_path.replace("'", "''")
            cols_describe = db.execute(
                f"DESCRIBE SELECT * FROM read_csv('{escaped_path}', all_varchar=True, auto_detect=True, header=True)"
            ).fetchall()
            
            cols_map = {row[0].lower(): row[0] for row in cols_describe}
            
            required_cols = [
                'transaction_id', 'sender_account', 'receiver_account',
                'sender_ifsc', 'receiver_ifsc', 'amount', 'timestamp',
                'payment_mode', 'narration', 'ip_address', 'device_type'
            ]
            
            missing_cols = [c for c in required_cols if c not in cols_map]
            if missing_cols:
                raise ValueError(f"Missing required column(s): {', '.join(missing_cols)}")
            
            select_clause = f"""
                "{cols_map['transaction_id']}" AS Transaction_ID,
                "{cols_map['sender_account']}" AS Sender_Account,
                "{cols_map['receiver_account']}" AS Receiver_Account,
                "{cols_map['sender_ifsc']}" AS Sender_IFSC,
                "{cols_map['receiver_ifsc']}" AS Receiver_IFSC,
                TRY_CAST("{cols_map['amount']}" AS DOUBLE) AS Amount,
                TRY_CAST("{cols_map['timestamp']}" AS TIMESTAMP) AS Timestamp,
                "{cols_map['payment_mode']}" AS Payment_Mode,
                "{cols_map['narration']}" AS Narration,
                "{cols_map['ip_address']}" AS IP_Address,
                "{cols_map['device_type']}" AS Device_Type
            """
            
            db.execute(f"""
            CREATE TABLE transactions AS 
            SELECT {select_clause}
            FROM read_csv('{escaped_path}', all_varchar=True, auto_detect=True, header=True)
            """)
            
        t_read = time.time() - t1
        INGEST_STATE['stage_times']['Reading & normalizing'] = round(t_read, 3)
        
        # --- STAGE: Indexing ---
        INGEST_STATE['current_stage'] = 'Indexing'
        t2 = time.time()
        
        with db_lock:
            db.execute("CREATE INDEX idx_sender ON transactions(Sender_Account)")
            db.execute("CREATE INDEX idx_receiver ON transactions(Receiver_Account)")
            db.execute("CREATE INDEX idx_txn_id ON transactions(Transaction_ID)")
            
        t_idx = time.time() - t2
        INGEST_STATE['stage_times']['Indexing'] = round(t_idx, 3)
        
        # --- STAGE: Fingerprinting ---
        INGEST_STATE['current_stage'] = 'Fingerprinting'
        t3 = time.time()
        
        with db_lock:
            row_count = db.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
            distinct_acc = db.execute("""
                SELECT COUNT(DISTINCT acc) FROM (
                    SELECT Sender_Account AS acc FROM transactions
                    UNION ALL
                    SELECT Receiver_Account AS acc FROM transactions
                )
            """).fetchone()[0]
            
            min_max_ts = db.execute("SELECT MIN(Timestamp), MAX(Timestamp) FROM transactions").fetchone()
            dup_txns = db.execute("""
                SELECT COUNT(Transaction_ID) - COUNT(DISTINCT Transaction_ID) 
                FROM transactions
            """).fetchone()[0]
            
            p99_amt = db.execute("SELECT QUANTILE_CONT(Amount, 0.99) FROM transactions").fetchone()[0]
            INGEST_STATE['p99_amount'] = round(float(p99_amt), 2)
            
        t_finger = time.time() - t3
        INGEST_STATE['stage_times']['Fingerprinting'] = round(t_finger, 3)
        
        total_time = time.time() - start_total_time
        
        date_range_str = "N/A"
        if min_max_ts and min_max_ts[0] and min_max_ts[1]:
            date_range_str = f"{str(min_max_ts[0])} to {str(min_max_ts[1])}"
            
        summary = {
            'file_name': os.path.basename(file_path),
            'full_path': file_path,
            'rows': row_count,
            'distinct_accounts': distinct_acc,
            'date_range': date_range_str,
            'duplicate_ids': dup_txns,
            'p99_amount': INGEST_STATE['p99_amount'],
            'per_stage_seconds': INGEST_STATE['stage_times'],
            'total_seconds': round(total_time, 3),
            'sha256': file_sha256
        }
        
        INGEST_STATE['current_stage'] = 'Done'
        INGEST_STATE['status'] = 'completed'
        INGEST_STATE['summary'] = summary
        INGEST_STATE['elapsed_sec'] = round(total_time, 3)
        INGEST_STATE['loaded'] = True

    except Exception as e:
        INGEST_STATE['status'] = 'error'
        INGEST_STATE['current_stage'] = 'Error'
        INGEST_STATE['error_message'] = str(e)
        INGEST_STATE['loaded'] = False


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/load', methods=['POST'])
def api_load():
    data = request.get_json(silent=True) or {}
    file_path = data.get('file_path', '').strip()
    
    if not file_path and 'file' in request.files:
        f = request.files['file']
        if f.filename:
            uploads_dir = os.path.join(app.root_path, 'uploads')
            os.makedirs(uploads_dir, exist_ok=True)
            saved_path = os.path.join(uploads_dir, f.filename)
            f.save(saved_path)
            file_path = saved_path
            
    if not file_path:
        return jsonify({'success': False, 'error': 'No file path or uploaded file provided'}), 400
        
    if INGEST_STATE['status'] == 'loading':
        return jsonify({'success': False, 'error': 'Ingestion already in progress'}), 400

    thread = threading.Thread(target=process_csv_ingestion, args=(file_path,))
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'message': 'Ingestion started'})


@app.route('/api/status', methods=['GET'])
def api_status():
    return jsonify(INGEST_STATE)


@app.route('/api/reset', methods=['POST'])
def api_reset():
    reset_ingest_state()
    return jsonify({'success': True, 'message': 'Dataset reset successfully'})


@app.route('/api/dataset_info', methods=['GET'])
def api_dataset_info():
    if not INGEST_STATE['loaded'] or not INGEST_STATE['summary']:
        return jsonify({'loaded': False})
    
    summary = INGEST_STATE['summary']
    return jsonify({
        'loaded': True,
        'dataset_name': summary['file_name'],
        'rows': summary['rows'],
        'load_time': summary['total_seconds'],
        'sha256': summary['sha256']
    })


@app.route('/api/risk_score', methods=['GET'])
def api_risk_score():
    if not INGEST_STATE['loaded']:
        return jsonify({'loaded': False, 'error': 'No dataset loaded'}), 400
        
    acc_id = request.args.get('account_id', '').strip()
    if not acc_id:
        return jsonify({'loaded': True, 'error': 'account_id parameter is required'}), 400
        
    with db_lock:
        risk_res = compute_account_risk_score(acc_id)
        
    return jsonify({
        'loaded': True,
        'account_id': acc_id,
        'risk_score': risk_res['risk_score'],
        'risk_band': risk_res['risk_band'],
        'flags': risk_res['flags']
    })


@app.route('/api/search', methods=['GET', 'POST'])
def api_search():
    if not INGEST_STATE['loaded']:
        return jsonify({'loaded': False, 'error': 'No dataset loaded'}), 400
        
    t0 = time.time()
    query = request.args.get('query', '').strip()
    if not query and request.is_json:
        data = request.get_json(silent=True) or {}
        query = data.get('query', '').strip()
        
    if not query:
        return jsonify({'loaded': True, 'found': False, 'error': 'Query string cannot be empty'}), 400

    with db_lock:
        resolved_from_txn = None
        target_account = query
        
        txn_match = db.execute(
            "SELECT Sender_Account, Transaction_ID FROM transactions WHERE Transaction_ID = ? LIMIT 1",
            [query]
        ).fetchone()
        
        if txn_match:
            target_account = txn_match[0]
            resolved_from_txn = txn_match[1]
            
        stats = db.execute("""
            SELECT 
                COALESCE(SUM(CASE WHEN direction = 'IN' THEN Amount ELSE 0 END), 0) AS total_in,
                COUNT(CASE WHEN direction = 'IN' THEN 1 END) AS count_in,
                COALESCE(SUM(CASE WHEN direction = 'OUT' THEN Amount ELSE 0 END), 0) AS total_out,
                COUNT(CASE WHEN direction = 'OUT' THEN 1 END) AS count_out,
                COUNT(DISTINCT counterparty) AS distinct_counterparties,
                MIN(Timestamp) AS first_activity,
                MAX(Timestamp) AS last_activity
            FROM (
                SELECT Receiver_Account AS counterparty, Amount, Timestamp, 'OUT' AS direction FROM transactions WHERE Sender_Account = ?
                UNION ALL
                SELECT Sender_Account AS counterparty, Amount, Timestamp, 'IN' AS direction FROM transactions WHERE Receiver_Account = ?
            ) t
        """, [target_account, target_account]).fetchone()
        
        total_in, count_in, total_out, count_out, distinct_cp, first_act, last_act = stats
        total_txns = count_in + count_out
        
        if total_txns == 0:
            prefix_pat = query + '%'
            acc_suggs = db.execute("""
                SELECT DISTINCT acc FROM (
                    SELECT Sender_Account AS acc FROM transactions WHERE Sender_Account LIKE ?
                    UNION
                    SELECT Receiver_Account AS acc FROM transactions WHERE Receiver_Account LIKE ?
                ) LIMIT 5
            """, [prefix_pat, prefix_pat]).fetchall()
            
            txn_suggs = db.execute("""
                SELECT DISTINCT Transaction_ID FROM transactions WHERE Transaction_ID LIKE ? LIMIT 5
            """, [prefix_pat]).fetchall()
            
            suggestions = [r[0] for r in acc_suggs] + [r[0] for r in txn_suggs]
            elapsed_ms = round((time.time() - t0) * 1000, 2)
            
            return jsonify({
                'loaded': True,
                'found': False,
                'query': query,
                'message': f"No record found for '{query}'",
                'suggestions': suggestions,
                'time_ms': elapsed_ms
            })

        txns_raw = db.execute("""
            WITH acc_txns AS (
                SELECT 
                    Transaction_ID, Timestamp, Amount, Payment_Mode, Narration, IP_Address, Device_Type,
                    'OUT' AS direction, Receiver_Account AS counterparty, Receiver_IFSC AS counterparty_ifsc
                FROM transactions WHERE Sender_Account = ?
                UNION ALL
                SELECT 
                    Transaction_ID, Timestamp, Amount, Payment_Mode, Narration, IP_Address, Device_Type,
                    'IN' AS direction, Sender_Account AS counterparty, Sender_IFSC AS counterparty_ifsc
                FROM transactions WHERE Receiver_Account = ?
            )
            SELECT * FROM acc_txns ORDER BY Timestamp DESC LIMIT 500
        """, [target_account, target_account]).fetchall()
        
        transactions_list = []
        for r in txns_raw:
            transactions_list.append({
                'txn_id': r[0],
                'timestamp': str(r[1]),
                'amount': round(float(r[2]), 2),
                'payment_mode': r[3],
                'narration': r[4],
                'ip_address': r[5],
                'device_type': r[6],
                'direction': r[7],
                'counterparty': r[8],
                'counterparty_ifsc': r[9]
            })

        risk_res = compute_account_risk_score(target_account)
        elapsed_ms = round((time.time() - t0) * 1000, 2)
        
        return jsonify({
            'loaded': True,
            'found': True,
            'query': query,
            'target_account': target_account,
            'resolved_from_txn': resolved_from_txn,
            'risk_score': risk_res['risk_score'],
            'risk_band': risk_res['risk_band'],
            'flags': risk_res['flags'],
            'stats': {
                'total_in': round(float(total_in), 2),
                'count_in': int(count_in),
                'total_out': round(float(total_out), 2),
                'count_out': int(count_out),
                'distinct_counterparties': int(distinct_cp),
                'first_activity': str(first_act) if first_act else None,
                'last_activity': str(last_act) if last_act else None
            },
            'transactions': transactions_list,
            'time_ms': elapsed_ms
        })


@app.route('/api/trace', methods=['GET', 'POST'])
def api_trace():
    if not INGEST_STATE['loaded']:
        return jsonify({'loaded': False, 'error': 'No dataset loaded'}), 400
        
    t0 = time.time()
    query = request.args.get('query', '').strip()
    if not query and request.is_json:
        data = request.get_json(silent=True) or {}
        query = data.get('query', '').strip()
        
    if not query:
        return jsonify({'loaded': True, 'found': False, 'error': 'Victim Account ID or Transaction ID is required'}), 400

    with db_lock:
        resolved_from_txn = None
        victim_acc = query
        
        txn_match = db.execute(
            "SELECT Sender_Account, Transaction_ID FROM transactions WHERE Transaction_ID = ? LIMIT 1",
            [query]
        ).fetchone()
        
        if txn_match:
            victim_acc = txn_match[0]
            resolved_from_txn = txn_match[1]
            
        acc_check = db.execute(
            "SELECT Sender_IFSC FROM transactions WHERE Sender_Account = ? UNION SELECT Receiver_IFSC FROM transactions WHERE Receiver_Account = ? LIMIT 1",
            [victim_acc, victim_acc]
        ).fetchone()
        
        if not acc_check:
            elapsed_sec = round(time.time() - t0, 3)
            return jsonify({
                'loaded': True,
                'found': False,
                'query': query,
                'message': f"No account or transactions found for '{query}'",
                'time_sec': elapsed_sec
            })

        victim_ifsc = acc_check[0] if acc_check and acc_check[0] else 'UNKNOWN'
        bank_prefix = victim_ifsc[:4].upper()
        bank_name = BANK_NAMES.get(bank_prefix, bank_prefix)
        
        nodes = {}
        edges = []
        
        nodes[victim_acc] = {
            'id': victim_acc,
            'bank': bank_name,
            'ifsc': victim_ifsc,
            'hop': 0,
            'layer': 'L0',
            'received': 0.0,
            'forwarded': 0.0,
            'held': 0.0,
            'first_time': None,
            'is_cashout': False
        }
        
        queue = [(victim_acc, 0)]
        visited_path = {victim_acc: 0}
        
        max_hops = CFG['TRACE_MAX_HOPS']
        max_nodes = CFG['TRACE_MAX_NODES']
        win_mins = CFG['TRACE_TIME_WINDOW_MINUTES']
        fwd_pct = CFG['TRACE_FORWARD_PCT']
        
        while queue and len(nodes) < max_nodes:
            curr_acc, curr_hop = queue.pop(0)
            
            if curr_hop >= max_hops:
                continue
                
            if curr_hop == 0:
                out_txns = db.execute("""
                    SELECT Transaction_ID, Receiver_Account, Receiver_IFSC, Amount, Timestamp, Payment_Mode, Narration, IP_Address, Device_Type
                    FROM transactions
                    WHERE Sender_Account = ?
                    ORDER BY Timestamp ASC
                """, [curr_acc]).fetchall()
                
                total_sent = 0.0
                for r in out_txns:
                    txn_id, rec_acc, rec_ifsc, amt, ts, pmode, narr, ip, dev = r
                    total_sent += amt
                    
                    if is_cashout_match(ip, dev, narr):
                        nodes[curr_acc]['is_cashout'] = True
                        
                    next_hop = curr_hop + 1
                    layer_str = f"L{min(next_hop, 3)}"
                    is_round_trip = (rec_acc in visited_path)
                    
                    if rec_acc not in nodes:
                        r_prefix = rec_ifsc[:4].upper() if rec_ifsc else 'UNKNOWN'
                        r_bank = BANK_NAMES.get(r_prefix, r_prefix)
                        nodes[rec_acc] = {
                            'id': rec_acc,
                            'bank': r_bank,
                            'ifsc': rec_ifsc,
                            'hop': next_hop,
                            'layer': layer_str,
                            'received': 0.0,
                            'forwarded': 0.0,
                            'held': 0.0,
                            'first_time': str(ts),
                            'is_cashout': is_cashout_match(ip, dev, narr)
                        }
                        if not is_round_trip:
                            queue.append((rec_acc, next_hop))
                            visited_path[rec_acc] = next_hop
                    else:
                        if is_cashout_match(ip, dev, narr):
                            nodes[rec_acc]['is_cashout'] = True
                            
                    nodes[rec_acc]['received'] += amt
                    
                    edges.append({
                        'from': curr_acc,
                        'to': rec_acc,
                        'amount': round(amt, 2),
                        'time': str(ts),
                        'txn_id': txn_id,
                        'mode': pmode,
                        'is_round_trip': is_round_trip
                    })
                    
                nodes[curr_acc]['forwarded'] = total_sent
                
            else:
                inc_edges = [e for e in edges if e['to'] == curr_acc]
                if not inc_edges:
                    continue
                    
                earliest_inc_ts = min(e['time'] for e in inc_edges)
                total_inc_amt = sum(e['amount'] for e in inc_edges)
                
                out_txns = db.execute(f"""
                    SELECT Transaction_ID, Receiver_Account, Receiver_IFSC, Amount, Timestamp, Payment_Mode, Narration, IP_Address, Device_Type
                    FROM transactions
                    WHERE Sender_Account = ? 
                      AND Timestamp >= TRY_CAST(? AS TIMESTAMP)
                      AND Timestamp <= TRY_CAST(? AS TIMESTAMP) + INTERVAL '{win_mins} minutes'
                    ORDER BY Timestamp ASC
                """, [curr_acc, earliest_inc_ts, earliest_inc_ts]).fetchall()
                
                sum_out = sum(r[3] for r in out_txns)
                
                if sum_out >= fwd_pct * total_inc_amt:
                    total_fwd = 0.0
                    for r in out_txns:
                        txn_id, rec_acc, rec_ifsc, amt, ts, pmode, narr, ip, dev = r
                        total_fwd += amt
                        
                        if is_cashout_match(ip, dev, narr):
                            nodes[curr_acc]['is_cashout'] = True
                            
                        next_hop = curr_hop + 1
                        layer_str = f"L{min(next_hop, 3)}"
                        is_round_trip = (rec_acc in visited_path)
                        
                        if rec_acc not in nodes:
                            r_prefix = rec_ifsc[:4].upper() if rec_ifsc else 'UNKNOWN'
                            r_bank = BANK_NAMES.get(r_prefix, r_prefix)
                            nodes[rec_acc] = {
                                'id': rec_acc,
                                'bank': r_bank,
                                'ifsc': rec_ifsc,
                                'hop': next_hop,
                                'layer': layer_str,
                                'received': 0.0,
                                'forwarded': 0.0,
                                'held': 0.0,
                                'first_time': str(ts),
                                'is_cashout': is_cashout_match(ip, dev, narr)
                            }
                            if next_hop < max_hops and not is_round_trip:
                                queue.append((rec_acc, next_hop))
                                visited_path[rec_acc] = next_hop
                        else:
                            if is_cashout_match(ip, dev, narr):
                                nodes[rec_acc]['is_cashout'] = True
                                
                        nodes[rec_acc]['received'] += amt
                        
                        edges.append({
                            'from': curr_acc,
                            'to': rec_acc,
                            'amount': round(amt, 2),
                            'time': str(ts),
                            'txn_id': txn_id,
                            'mode': pmode,
                            'is_round_trip': is_round_trip
                        })
                        
                    nodes[curr_acc]['forwarded'] += total_fwd

        # Attach Risk Score & Red Flags to each node
        for n in nodes.values():
            n['received'] = round(n['received'], 2)
            n['forwarded'] = round(n['forwarded'], 2)
            n['held'] = round(max(0.0, n['received'] - n['forwarded']), 2)
            
            risk_info = compute_account_risk_score(n['id'])
            n['risk_score'] = risk_info['risk_score']
            n['risk_band'] = risk_info['risk_band']
            n['flags'] = risk_info['flags']

        amt_sent_by_victim = nodes[victim_acc]['forwarded']
        amt_reaching_cashout = sum(n['received'] for n in nodes.values() if n['is_cashout'] and n['hop'] > 0)
        amt_still_held = sum(n['held'] for n in nodes.values() if not n['is_cashout'] and n['hop'] > 0)
        
        elapsed_sec = round(time.time() - t0, 3)
        
        return jsonify({
            'loaded': True,
            'found': True,
            'query': query,
            'victim_account': victim_acc,
            'resolved_from_txn': resolved_from_txn,
            'nodes': list(nodes.values()),
            'edges': edges,
            'summary': {
                'amount_sent_by_victim': round(amt_sent_by_victim, 2),
                'amount_reaching_cashout': round(amt_reaching_cashout, 2),
                'amount_still_held': round(amt_still_held, 2),
                'total_nodes': len(nodes),
                'total_edges': len(edges)
            },
            'time_sec': elapsed_sec
        })


# ==============================================================================
# STAGE 5: OFFICIAL PRINTABLE CASE DIARY & BANK FREEZE NOTICES
# ==============================================================================
@app.route('/report')
def render_report():
    if not INGEST_STATE['loaded']:
        return "No dataset loaded. Please load a dataset first.", 400
        
    victim_acc = request.args.get('victim', '').strip()
    if not victim_acc:
        return "victim parameter required.", 400

    # Fetch trace data
    with db_lock:
        nodes = {}
        edges = []
        
        acc_check = db.execute(
            "SELECT Sender_IFSC FROM transactions WHERE Sender_Account = ? UNION SELECT Receiver_IFSC FROM transactions WHERE Receiver_Account = ? LIMIT 1",
            [victim_acc, victim_acc]
        ).fetchone()
        
        if not acc_check:
            return f"Victim account {victim_acc} not found in database.", 404

        victim_ifsc = acc_check[0] if acc_check and acc_check[0] else 'UNKNOWN'
        bank_prefix = victim_ifsc[:4].upper()
        bank_name = BANK_NAMES.get(bank_prefix, bank_prefix)
        
        nodes[victim_acc] = {
            'id': victim_acc,
            'bank': bank_name,
            'ifsc': victim_ifsc,
            'hop': 0,
            'layer': 'L0',
            'received': 0.0,
            'forwarded': 0.0,
            'held': 0.0,
            'first_time': None,
            'is_cashout': False
        }
        
        queue = [(victim_acc, 0)]
        visited_path = {victim_acc: 0}
        
        while queue and len(nodes) < CFG['TRACE_MAX_NODES']:
            curr_acc, curr_hop = queue.pop(0)
            if curr_hop >= CFG['TRACE_MAX_HOPS']:
                continue
                
            if curr_hop == 0:
                out_txns = db.execute("""
                    SELECT Transaction_ID, Receiver_Account, Receiver_IFSC, Amount, Timestamp, Payment_Mode, Narration, IP_Address, Device_Type
                    FROM transactions
                    WHERE Sender_Account = ?
                    ORDER BY Timestamp ASC
                """, [curr_acc]).fetchall()
                
                total_sent = 0.0
                for r in out_txns:
                    txn_id, rec_acc, rec_ifsc, amt, ts, pmode, narr, ip, dev = r
                    total_sent += amt
                    
                    if is_cashout_match(ip, dev, narr):
                        nodes[curr_acc]['is_cashout'] = True
                        
                    next_hop = curr_hop + 1
                    layer_str = f"L{min(next_hop, 3)}"
                    is_round_trip = (rec_acc in visited_path)
                    
                    if rec_acc not in nodes:
                        r_prefix = rec_ifsc[:4].upper() if rec_ifsc else 'UNKNOWN'
                        r_bank = BANK_NAMES.get(r_prefix, r_prefix)
                        nodes[rec_acc] = {
                            'id': rec_acc,
                            'bank': r_bank,
                            'ifsc': rec_ifsc,
                            'hop': next_hop,
                            'layer': layer_str,
                            'received': 0.0,
                            'forwarded': 0.0,
                            'held': 0.0,
                            'first_time': str(ts),
                            'is_cashout': is_cashout_match(ip, dev, narr)
                        }
                        if not is_round_trip:
                            queue.append((rec_acc, next_hop))
                            visited_path[rec_acc] = next_hop
                    else:
                        if is_cashout_match(ip, dev, narr):
                            nodes[rec_acc]['is_cashout'] = True
                            
                    nodes[rec_acc]['received'] += amt
                    edges.append({
                        'from': curr_acc,
                        'to': rec_acc,
                        'amount': round(amt, 2),
                        'time': str(ts),
                        'txn_id': txn_id,
                        'mode': pmode,
                        'is_round_trip': is_round_trip
                    })
                nodes[curr_acc]['forwarded'] = total_sent
                
            else:
                inc_edges = [e for e in edges if e['to'] == curr_acc]
                if not inc_edges:
                    continue
                earliest_inc_ts = min(e['time'] for e in inc_edges)
                total_inc_amt = sum(e['amount'] for e in inc_edges)
                
                out_txns = db.execute(f"""
                    SELECT Transaction_ID, Receiver_Account, Receiver_IFSC, Amount, Timestamp, Payment_Mode, Narration, IP_Address, Device_Type
                    FROM transactions
                    WHERE Sender_Account = ? 
                      AND Timestamp >= TRY_CAST(? AS TIMESTAMP)
                      AND Timestamp <= TRY_CAST(? AS TIMESTAMP) + INTERVAL '{CFG["TRACE_TIME_WINDOW_MINUTES"]} minutes'
                    ORDER BY Timestamp ASC
                """, [curr_acc, earliest_inc_ts, earliest_inc_ts]).fetchall()
                
                sum_out = sum(r[3] for r in out_txns)
                if sum_out >= CFG['TRACE_FORWARD_PCT'] * total_inc_amt:
                    total_fwd = 0.0
                    for r in out_txns:
                        txn_id, rec_acc, rec_ifsc, amt, ts, pmode, narr, ip, dev = r
                        total_fwd += amt
                        if is_cashout_match(ip, dev, narr):
                            nodes[curr_acc]['is_cashout'] = True
                        next_hop = curr_hop + 1
                        layer_str = f"L{min(next_hop, 3)}"
                        is_round_trip = (rec_acc in visited_path)
                        if rec_acc not in nodes:
                            r_prefix = rec_ifsc[:4].upper() if rec_ifsc else 'UNKNOWN'
                            r_bank = BANK_NAMES.get(r_prefix, r_prefix)
                            nodes[rec_acc] = {
                                'id': rec_acc,
                                'bank': r_bank,
                                'ifsc': rec_ifsc,
                                'hop': next_hop,
                                'layer': layer_str,
                                'received': 0.0,
                                'forwarded': 0.0,
                                'held': 0.0,
                                'first_time': str(ts),
                                'is_cashout': is_cashout_match(ip, dev, narr)
                            }
                            if next_hop < CFG['TRACE_MAX_HOPS'] and not is_round_trip:
                                queue.append((rec_acc, next_hop))
                                visited_path[rec_acc] = next_hop
                        else:
                            if is_cashout_match(ip, dev, narr):
                                nodes[rec_acc]['is_cashout'] = True
                        nodes[rec_acc]['received'] += amt
                        edges.append({
                            'from': curr_acc,
                            'to': rec_acc,
                            'amount': round(amt, 2),
                            'time': str(ts),
                            'txn_id': txn_id,
                            'mode': pmode,
                            'is_round_trip': is_round_trip
                        })
                    nodes[curr_acc]['forwarded'] += total_fwd

        for n in nodes.values():
            n['received'] = round(n['received'], 2)
            n['forwarded'] = round(n['forwarded'], 2)
            n['held'] = round(max(0.0, n['received'] - n['forwarded']), 2)
            risk_info = compute_account_risk_score(n['id'])
            n['risk_score'] = risk_info['risk_score']
            n['risk_band'] = risk_info['risk_band']

        amt_sent_by_victim = nodes[victim_acc]['forwarded']
        amt_reaching_cashout = sum(n['received'] for n in nodes.values() if n['is_cashout'] and n['hop'] > 0)
        amt_still_held = sum(n['held'] for n in nodes.values() if not n['is_cashout'] and n['hop'] > 0)

        # Group accounts by bank for Freeze Notices
        freeze_by_bank = {}
        for e in edges:
            to_acc = e['to']
            node_info = nodes.get(to_acc, {})
            bank_name = node_info.get('bank', 'Unknown Bank')
            if bank_name not in freeze_by_bank:
                freeze_by_bank[bank_name] = []
            freeze_by_bank[bank_name].append({
                'account_id': to_acc,
                'ifsc': node_info.get('ifsc', ''),
                'txn_id': e['txn_id'],
                'amount': e['amount'],
                'time': e['time'],
                'risk_score': node_info.get('risk_score', 0),
                'risk_band': node_info.get('risk_band', 'Low')
            })

    gen_time = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
    file_sha256 = INGEST_STATE['summary']['sha256'] if INGEST_STATE['summary'] else 'N/A'

    # Render HTML template string for Report
    report_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Official Case Diary & Bank Freeze Notices - Case #{victim_acc}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; color: #12332b; padding: 40px; background-color: #ffffff; line-height: 1.5; }}
        .header-block {{ border-bottom: 2px solid #12332b; padding-bottom: 16px; margin-bottom: 24px; display: flex; justify-content: space-between; align-items: flex-end; }}
        .title {{ font-size: 22px; font-weight: 800; color: #12332b; }}
        .subtitle {{ font-size: 13px; color: #52756b; margin-top: 4px; }}
        .meta-box {{ background-color: #f7faf8; border: 1px solid #e2ece8; border-radius: 8px; padding: 16px; margin-bottom: 24px; font-size: 13px; }}
        .grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }}
        .metric-title {{ font-size: 11px; color: #8ca89f; font-weight: 700; }}
        .metric-val {{ font-size: 16px; font-weight: 800; color: #12332b; margin-top: 2px; }}
        .section-title {{ font-size: 16px; font-weight: 700; border-bottom: 1px solid #e2ece8; padding-bottom: 6px; margin: 28px 0 14px 0; color: #12332b; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 12px; margin-bottom: 20px; }}
        th, td {{ padding: 8px 10px; border: 1px solid #e2ece8; text-align: left; }}
        th {{ background-color: #f1f6f4; font-weight: 700; color: #12332b; }}
        .mono {{ font-family: monospace; }}
        .notice-card {{ page-break-before: always; border: 1px solid #12332b; padding: 28px; border-radius: 8px; margin-top: 30px; background-color: #ffffff; }}
        .legal-box {{ background-color: #eefbf7; border: 1px solid #c4eedf; padding: 14px; border-radius: 6px; font-size: 12px; color: #12332b; margin: 16px 0; font-weight: 500; }}
        .footer {{ font-size: 11px; color: #8ca89f; margin-top: 24px; border-top: 1px solid #e2ece8; padding-top: 12px; display: flex; justify-content: space-between; }}
        .btn-print {{ background-color: #3ecfa4; color: #12332b; border: none; padding: 10px 20px; font-weight: 700; border-radius: 6px; cursor: pointer; float: right; margin-bottom: 20px; }}
        @media print {{ .btn-print {{ display: none; }} body {{ padding: 20px; }} .notice-card {{ page-break-before: always; }} }}
    </style>
</head>
<body>
    <button class="btn-print" onclick="window.print()">Print Report / Save PDF</button>
    
    <div class="header-block">
        <div>
            <div class="title">CYBER CRIME INVESTIGATION UNIT</div>
            <div class="subtitle">CASE DIARY & MULTI-HOP MONEY MULE FREEZE DIRECTIVE</div>
        </div>
        <div style="text-align: right; font-size: 12px; color: #52756b;">
            <div>Report Date: {gen_time}</div>
            <div>Dataset SHA-256: <span class="mono">{file_sha256[:16]}...</span></div>
        </div>
    </div>

    <div class="meta-box">
        <div class="grid">
            <div>
                <div class="metric-title">VICTIM ACCOUNT ID</div>
                <div class="metric-val mono">{victim_acc}</div>
            </div>
            <div>
                <div class="metric-title">TOTAL SIPHONED AMOUNT</div>
                <div class="metric-val" style="color: #d97706;">₹{amt_sent_by_victim:,.2f}</div>
            </div>
            <div>
                <div class="metric-title">AMOUNT AT CASHOUT NODES</div>
                <div class="metric-val" style="color: #9b1c1c;">₹{amt_reaching_cashout:,.2f}</div>
            </div>
        </div>
    </div>

    <div class="section-title">1. Layer-Wise Account Summary</div>
    <table>
        <thead>
            <tr>
                <th>Layer</th>
                <th>Account ID</th>
                <th>Bank Name</th>
                <th>IFSC</th>
                <th>Received (₹)</th>
                <th>Forwarded (₹)</th>
                <th>Held (₹)</th>
                <th>Risk Band</th>
            </tr>
        </thead>
        <tbody>
"""
    for n in nodes.values():
        report_html += f"""
            <tr>
                <td>{n['layer']} (Hop {n['hop']})</td>
                <td class="mono">{n['id']}</td>
                <td>{n['bank']}</td>
                <td class="mono">{n['ifsc']}</td>
                <td>₹{n['received']:,.2f}</td>
                <td>₹{n['forwarded']:,.2f}</td>
                <td>₹{n['held']:,.2f}</td>
                <td><b>{n['risk_score']}/100 ({n['risk_band']})</b></td>
            </tr>
        """

    report_html += """
        </tbody>
    </table>

    <div class="section-title">2. Priority Accounts Recommended for Immediate Freeze</div>
    <table>
        <thead>
            <tr>
                <th>Account ID</th>
                <th>Bank Name</th>
                <th>IFSC</th>
                <th>Held Balance (₹)</th>
                <th>Risk Score</th>
                <th>Action Directive</th>
            </tr>
        </thead>
        <tbody>
"""
    # Freeze priority accounts (held > 0 or high risk)
    freeze_nodes = [n for n in nodes.values() if n['hop'] > 0 and (n['held'] > 0 or n['risk_score'] >= 50)]
    for fn in freeze_nodes:
        report_html += f"""
            <tr>
                <td class="mono"><b>{fn['id']}</b></td>
                <td>{fn['bank']}</td>
                <td class="mono">{fn['ifsc']}</td>
                <td><b>₹{fn['held']:,.2f}</b></td>
                <td>{fn['risk_score']}/100 ({fn['risk_band']})</td>
                <td style="color: #9b1c1c; font-weight: 700;">DEBIT FREEZE IMMEDIATELY</td>
            </tr>
        """

    report_html += """
        </tbody>
    </table>

    <div class="footer">
        <div>Generated by Offline Money-Mule Tracing System</div>
        <div>Dataset SHA-256: """ + file_sha256 + """</div>
    </div>
"""

    # Add Official Bank Freeze Notices
    notice_idx = 1
    for bank, b_txns in freeze_by_bank.items():
        report_html += f"""
        <div class="notice-card">
            <div style="text-align: center; border-bottom: 2px solid #12332b; padding-bottom: 12px; margin-bottom: 20px;">
                <h3 style="margin: 0; font-size: 18px;">OFFICIAL BANK FREEZE NOTICE #{notice_idx}</h3>
                <div style="font-size: 12px; color: #52756b; margin-top: 4px;">URGENT LEGAL DIRECTIVE - CYBER CRIME INVESTIGATION</div>
            </div>

            <div style="font-size: 13px; margin-bottom: 16px;">
                <b>TO:</b> Nodal Officer / Manager (Cyber Cell Escalations)<br>
                <b>BANK:</b> {bank}<br>
                <b>DATE:</b> {gen_time}
            </div>

            <div class="legal-box">
                {LEGAL_SECTION_TEXT}
            </div>

            <div style="font-size: 13px; font-weight: 700; margin-bottom: 8px;">DISPUTED BENEFICIARY ACCOUNTS TO BE FROZEN:</div>
            <table>
                <thead>
                    <tr>
                        <th>Beneficiary Account</th>
                        <th>IFSC Code</th>
                        <th>Disputed Txn ID</th>
                        <th>Amount (₹)</th>
                        <th>Txn Timestamp</th>
                        <th>Risk Level</th>
                    </tr>
                </thead>
                <tbody>
        """
        for bt in b_txns:
            report_html += f"""
                    <tr>
                        <td class="mono"><b>{bt['account_id']}</b></td>
                        <td class="mono">{bt['ifsc']}</td>
                        <td class="mono">{bt['txn_id']}</td>
                        <td><b>₹{bt['amount']:,.2f}</b></td>
                        <td>{bt['time']}</td>
                        <td>{bt['risk_score']}/100 ({bt['risk_band']})</td>
                    </tr>
            """
        report_html += f"""
                </tbody>
            </table>

            <div style="margin-top: 30px; display: flex; justify-content: space-between; font-size: 12px; border-top: 1px dashed #12332b; padding-top: 16px;">
                <div>
                    <b>Investigating Officer Signature:</b> ___________________________<br>
                    Cyber Crime Division, Police Dept.
                </div>
                <div style="text-align: right;">
                    <b>Dataset SHA-256:</b><br>
                    <span class="mono" style="font-size: 10px;">{file_sha256}</span>
                </div>
            </div>
        </div>
        """
        notice_idx += 1

    report_html += "</body></html>"
    return report_html


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
