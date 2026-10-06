import duckdb
import time

con = duckdb.connect()
csv_path = r"C:\Users\vaish\cyberhack\data\uploads\VoidHacks8_MuleAccount_2M_Transactions.csv"
con.execute(f"""
CREATE TABLE transactions AS 
SELECT 
    Transaction_ID, Sender_Account, Receiver_Account, Sender_IFSC, Receiver_IFSC,
    TRY_CAST(Amount AS DOUBLE) AS Amount, TRY_CAST(Timestamp AS TIMESTAMP) AS Timestamp,
    Payment_Mode, Narration, IP_Address, Device_Type
FROM read_csv('{csv_path}', all_varchar=True, auto_detect=True, header=True)
""")
con.execute("CREATE INDEX idx_sender ON transactions(Sender_Account)")
con.execute("CREATE INDEX idx_receiver ON transactions(Receiver_Account)")
con.execute("CREATE INDEX idx_txn_id ON transactions(Transaction_ID)")

# Find 5 candidate victim senders with narration starting with UPI/REF/TASK
victims = [r[0] for r in con.execute("""
    SELECT DISTINCT Sender_Account 
    FROM transactions 
    WHERE Narration LIKE 'UPI/REF/TASK%' 
    LIMIT 5
""").fetchall()]

print("5 Test Victim Senders:", victims)

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
    'CNRB': 'Canara Bank'
}

def is_cashout_match(ip, device, narration):
    if ip and (ip.startswith('185.') or ip.startswith('194.')):
        return True
    if device in ('Web_Emulator', 'Linux_Script'):
        return True
    if narration:
        upper_nar = narration.upper()
        if 'WALLET' in upper_nar or 'CRYPTO' in upper_nar or 'P2P' in upper_nar:
            return True
    return False

def trace_money(victim_acc):
    t0 = time.time()
    
    nodes = {}  # acc_id -> dict
    edges = []
    
    # Init victim node (L0)
    victim_ifsc = con.execute("SELECT Sender_IFSC FROM transactions WHERE Sender_Account = ? LIMIT 1", [victim_acc]).fetchone()
    ifsc_val = victim_ifsc[0] if victim_ifsc else 'UNKNOWN'
    bank_prefix = ifsc_val[:4].upper()
    bank_name = BANK_NAMES.get(bank_prefix, bank_prefix)
    
    nodes[victim_acc] = {
        'id': victim_acc,
        'bank': bank_name,
        'ifsc': ifsc_val,
        'hop': 0,
        'layer': 'L0',
        'received': 0.0,
        'forwarded': 0.0,
        'held': 0.0,
        'first_time': None,
        'is_cashout': False
    }
    
    queue = [(victim_acc, 0)]  # (account_id, hop)
    visited_nodes = {victim_acc: 0}
    
    while queue and len(nodes) < 500:
        curr_acc, curr_hop = queue.pop(0)
        
        if curr_hop >= 4:
            continue
            
        # Find incoming trace flows to curr_acc (unless victim at hop 0)
        if curr_hop == 0:
            # Victim outgoing transfers
            out_txns = con.execute("""
                SELECT Transaction_ID, Receiver_Account, Receiver_IFSC, Amount, Timestamp, Payment_Mode, Narration, IP_Address, Device_Type
                FROM transactions
                WHERE Sender_Account = ?
                ORDER BY Timestamp ASC
            """, [curr_acc]).fetchall()
            
            total_sent = 0.0
            for r in out_txns:
                txn_id, rec_acc, rec_ifsc, amt, ts, pmode, narr, ip, dev = r
                total_sent += amt
                
                # Check cashout on victim outgoing
                if is_cashout_match(ip, dev, narr):
                    nodes[curr_acc]['is_cashout'] = True
                    
                next_hop = curr_hop + 1
                layer_str = f"L{min(next_hop, 3)}"
                
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
                    queue.append((rec_acc, next_hop))
                    visited_nodes[rec_acc] = next_hop
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
                    'mode': pmode
                })
                
            nodes[curr_acc]['forwarded'] = total_sent
            
        else:
            # Intermediate Mule Node at Hop 1, 2, 3
            # Get earliest incoming timestamp and total received in trace
            inc_edges = [e for e in edges if e['to'] == curr_acc]
            if not inc_edges:
                continue
                
            earliest_inc_ts = min(e['time'] for e in inc_edges)
            total_inc_amt = sum(e['amount'] for e in inc_edges)
            
            # Find candidate outgoing transfers in 30-minute window
            out_txns = con.execute("""
                SELECT Transaction_ID, Receiver_Account, Receiver_IFSC, Amount, Timestamp, Payment_Mode, Narration, IP_Address, Device_Type
                FROM transactions
                WHERE Sender_Account = ? 
                  AND Timestamp >= TRY_CAST(? AS TIMESTAMP)
                  AND Timestamp <= TRY_CAST(? AS TIMESTAMP) + INTERVAL '30 minutes'
                ORDER BY Timestamp ASC
            """, [curr_acc, earliest_inc_ts, earliest_inc_ts]).fetchall()
            
            sum_out = sum(r[3] for r in out_txns)
            
            # Forwarding threshold rule: sum_out >= 85% of total_inc_amt
            if sum_out >= 0.85 * total_inc_amt:
                total_fwd = 0.0
                for r in out_txns:
                    txn_id, rec_acc, rec_ifsc, amt, ts, pmode, narr, ip, dev = r
                    total_fwd += amt
                    
                    if is_cashout_match(ip, dev, narr):
                        nodes[curr_acc]['is_cashout'] = True
                        
                    next_hop = curr_hop + 1
                    layer_str = f"L{min(next_hop, 3)}"
                    
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
                        if next_hop < 4:
                            queue.append((rec_acc, next_hop))
                        visited_nodes[rec_acc] = next_hop
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
                        'mode': pmode
                    })
                    
                nodes[curr_acc]['forwarded'] += total_fwd

    # Calculate held amounts for all nodes
    for n in nodes.values():
        n['received'] = round(n['received'], 2)
        n['forwarded'] = round(n['forwarded'], 2)
        n['held'] = round(max(0.0, n['received'] - n['forwarded']), 2)
        
    amt_sent_by_victim = nodes[victim_acc]['forwarded']
    amt_reaching_cashout = sum(n['received'] for n in nodes.values() if n['is_cashout'] and n['hop'] > 0)
    amt_still_held = sum(n['held'] for n in nodes.values() if not n['is_cashout'] and n['hop'] > 0)
    
    elapsed = time.time() - t0
    
    return {
        'victim': victim_acc,
        'nodes': list(nodes.values()),
        'edges': edges,
        'summary': {
            'amount_sent_by_victim': round(amt_sent_by_victim, 2),
            'amount_reaching_cashout': round(amt_reaching_cashout, 2),
            'amount_still_held': round(amt_still_held, 2),
            'total_nodes': len(nodes),
            'total_edges': len(edges)
        },
        'time_sec': round(elapsed, 3)
    }

for v in victims:
    res = trace_money(v)
    print(f"Victim: {v} | Nodes: {res['summary']['total_nodes']} | Edges: {res['summary']['total_edges']} | Sent: Rs. {res['summary']['amount_sent_by_victim']:,.2f} | Cashout: Rs. {res['summary']['amount_reaching_cashout']:,.2f} | Held: Rs. {res['summary']['amount_still_held']:,.2f} | Time: {res['time_sec']} s")
