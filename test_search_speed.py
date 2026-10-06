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

accs = [r[0] for r in con.execute("SELECT Sender_Account FROM transactions LIMIT 3").fetchall()]
print("Testing Search on accounts:", accs)

for acc in accs:
    t0 = time.time()
    
    # 1. Stats
    stats = con.execute("""
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
    """, [acc, acc]).fetchone()
    
    # 2. Top 500 txns
    txns = con.execute("""
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
    """, [acc, acc]).fetchall()
    
    elapsed = time.time() - t0
    print(f"Account: {acc} | Total In: {stats[0]:.2f} ({stats[1]} txns) | Total Out: {stats[2]:.2f} ({stats[3]} txns) | Counterparties: {stats[4]} | Time: {elapsed*1000:.2f} ms")
