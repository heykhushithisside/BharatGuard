import re
import base64
import sqlite3
import hashlib
import time
import streamlit as st
import graphviz

# ============================================================
# BHARATGUARD: FULL-STACK UPI PORTAL & DFA SCAM DETECTOR
# Python + Streamlit + SQLite Database + DFA Backend
# ============================================================

st.set_page_config(
    page_title="BharatGuard | UPI Payment Portal",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------- DATABASE SETUP (SQLite) ----------------

def get_db_connection():
    conn = sqlite3.connect("upi_system.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            upi_id TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            bank_name TEXT NOT NULL,
            account_number TEXT NOT NULL,
            balance REAL DEFAULT 10000.0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Transactions Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_vpa TEXT NOT NULL,
            receiver_vpa TEXT NOT NULL,
            amount REAL NOT NULL,
            note TEXT,
            status TEXT NOT NULL,
            dfa_state INTEGER,
            risk_flag INTEGER DEFAULT 0,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.commit()
    conn.close()

# Initialize DB on app startup
init_db()

# Helper function to hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Helper function to convert local image to Base64
def get_base64_image(image_path):
    try:
        with open(image_path, "rb") as img_file:
            encoded = base64.b64encode(img_file.read()).decode()
            return f"data:image/png;base64,{encoded}"
    except FileNotFoundError:
        return ""

shield_base64 = get_base64_image("shield.png")

# ---------------- DFA AUTOMATA ENGINE ----------------

U = 1       # Urgency
L = 2       # Link / verification
S = 4       # Sensitive information
R = 8       # Reward / refund
OTHER = 0   # Any other word

CATEGORY_NAMES = {
    U: "Urgency",
    L: "Link / verification",
    S: "Sensitive information",
    R: "Reward / refund"
}

CATEGORY_SYMBOLS = {
    U: "U",
    L: "L",
    S: "S",
    R: "R",
    OTHER: "O"
}

KEYWORDS = {
    U: {
        "urgent", "immediately", "blocked", "block",
        "suspended", "expire", "today", "now", "hurry",
        "turant", "jaldi", "band", "khata"
    },
    L: {
        "click", "link", "verify", "verification",
        "update", "kyc", "website", "http", "https",
        "link_par", "click_kare"
    },
    S: {
        "pin", "password", "otp", "cvv", "mpin",
        "upi-pin", "passcode", "atm", "number"
    },
    R: {
        "refund", "cashback", "reward", "prize",
        "won", "winner", "claim", "receive", "gift",
        "jeeto", "inami", "paisa", "rupaye"
    }
}

def get_symbol(word):
    for category, keywords in KEYWORDS.items():
        if word in keywords:
            return category
    return OTHER

def transition(state, symbol):
    return state | symbol

def describe_state(state):
    return [name for bit, name in CATEGORY_NAMES.items() if state & bit]

def analyze_message(message):
    words = re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)*", message.lower())
    state = 0
    trace = [{
        "Step": 0,
        "Input": "START",
        "Symbol": "—",
        "Before": 0,
        "After": 0,
        "Detected categories": "None"
    }]

    for step, word in enumerate(words, start=1):
        symbol = get_symbol(word)
        new_state = transition(state, symbol)
        categories = describe_state(new_state)

        trace.append({
            "Step": step,
            "Input": word,
            "Symbol": CATEGORY_SYMBOLS[symbol],
            "Before": state,
            "After": new_state,
            "Detected categories": (", ".join(categories) if categories else "None")
        })
        state = new_state

    urgency_and_link = bool(state & U) and bool(state & L)
    sensitive_present = bool(state & S)
    suspicious = urgency_and_link or sensitive_present
    indicators = describe_state(state)

    if urgency_and_link and sensitive_present:
        reason = "Critical risk: Combines urgency, verification links, and sensitive credential demands."
        advice = "Do not click links or share your UPI PIN/OTP. Verify through your official banking app."
    elif urgency_and_link:
        reason = "High risk: Urgency paired with external verification links detected."
        advice = "Avoid external links. Open your trusted payment app directly to check account status."
    elif sensitive_present:
        reason = "High risk: Remarks attempt to solicit sensitive financial codes or PINs."
        advice = "Never disclose your UPI PIN, MPIN, or OTP to anyone under any circumstance."
    elif state & R:
        reason = "Moderate risk: Reward or refund mentions found, requiring caution."
        advice = "Beware of unsolicited cashback offers requiring fees or credential sharing."
    else:
        reason = "No high-risk pattern matching the predefined automata rules was identified."
        advice = "Standard transaction note, but always maintain cautious digital hygiene."

    return {
        "suspicious": suspicious,
        "state": state,
        "indicators": indicators,
        "reason": reason,
        "advice": advice,
        "trace": trace,
        "words": words
    }

def generate_state_graph(trace):
    dot = graphviz.Digraph(comment='DFA Trace', format='svg')
    dot.attr(bgcolor='transparent', rankdir='LR', fontname='Inter', fontsize='12')
    dot.attr('node', shape='box', style='rounded,filled', fillcolor='#1e112d', color='#d946ef', fontcolor='#f3e8ff', fontname='Inter', margin='0.2')
    dot.attr('edge', color='#c084fc', fontcolor='#e879f9', fontname='Inter', fontsize='10')

    for i in range(len(trace) - 1):
        curr = trace[i]
        nxt = trace[i+1]
        node_from_id = f"step_{curr['Step']}_{curr['After']}"
        node_to_id = f"step_{nxt['Step']}_{nxt['After']}"
        from_label = f"Step {curr['Step']}\nState: {curr['After']}" if curr['Step'] > 0 else "Start\nState: 0"
        to_label = f"Step {nxt['Step']}\nState: {nxt['After']}"
        dot.node(node_from_id, from_label)
        dot.node(node_to_id, to_label)
        edge_label = f"'{nxt['Input']}'\n[{nxt['Symbol']}]"
        dot.edge(node_from_id, node_to_id, label=edge_label)

    return dot

# ---------------- GLASSMORPHIC CSS ----------------

st.markdown(f"""
<style>
    .stApp {{
        background: linear-gradient(135deg, rgba(15, 7, 21, 0.94) 0%, rgba(22, 9, 36, 0.94) 50%, rgba(31, 12, 51, 0.94) 100%),
                    url('{shield_base64}');
        background-repeat: no-repeat;
        background-position: center center;
        background-size: 50vh;
        background-attachment: fixed;
        color: #f3e8ff;
        font-family: 'Inter', sans-serif;
    }}

    .block-container {{
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 1200px;
    }}

    .cyber-hero {{
        background: rgba(31, 14, 51, 0.7);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border: 1px solid rgba(217, 70, 239, 0.25);
        border-radius: 20px;
        padding: 35px;
        box-shadow: 0 8px 32px 0 rgba(15, 7, 21, 0.5);
        display: flex;
        align-items: center;
        gap: 30px;
        margin-bottom: 25px;
    }}

    .cyber-shield-container {{
        width: 150px;
        height: 150px;
        background: rgba(31, 14, 51, 0.4);
        border: 2px solid rgba(217, 70, 239, 0.3);
        border-radius: 22px;
        display: flex;
        align-items: center;
        justify-content: center;
        box-shadow: 0 0 25px rgba(217, 70, 239, 0.4);
        flex-shrink: 0;
        overflow: hidden;
        padding: 10px;
    }}

    .cyber-shield-container img {{
        width: 100%;
        height: 100%;
        object-fit: contain;
        filter: drop-shadow(0 0 10px rgba(192, 132, 252, 0.7));
    }}

    .hero-text h1 {{
        color: #fae8ff;
        font-weight: 800;
        margin-bottom: 4px;
        font-size: 2.3rem;
        letter-spacing: -0.5px;
    }}

    .hero-text p {{
        color: #d8b4fe;
        margin: 0;
        font-size: 1.05rem;
    }}

    .glass-card {{
        background: rgba(26, 12, 42, 0.65);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid rgba(192, 132, 252, 0.18);
        border-radius: 16px;
        padding: 20px;
        margin-bottom: 16px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
    }}

    div[data-testid="stMetric"] {{
        background: rgba(31, 14, 51, 0.75);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(217, 70, 239, 0.2);
        padding: 16px;
        border-radius: 14px;
    }}
    div[data-testid="stMetric"] label {{
        color: #d8b4fe !important;
    }}
    div[data-testid="stMetric"] div[data-testid="stMetricValue"] {{
        color: #f3e8ff !important;
    }}

    div.stButton > button {{
        background: linear-gradient(135deg, #c084fc 0%, #9333ea 100%);
        color: white;
        border-radius: 12px;
        border: none;
        min-height: 48px;
        font-weight: 600;
        box-shadow: 0 4px 15px rgba(147, 51, 234, 0.4);
        transition: all 0.3s ease;
    }}
    div.stButton > button:hover {{
        background: linear-gradient(135deg, #d946ef 0%, #a855f7 100%);
        box-shadow: 0 6px 20px rgba(217, 70, 239, 0.6);
    }}

    [data-testid="stDataFrame"] {{
        border: 1px solid rgba(192, 132, 252, 0.2);
        border-radius: 12px;
        overflow: hidden;
    }}

    [data-testid="stSidebar"] {{
        background-color: rgba(11, 5, 16, 0.95);
        border-right: 1px solid rgba(192, 132, 252, 0.15);
    }}
</style>
""", unsafe_allow_html=True)

# ---------------- SESSION STATE MANAGEMENT ----------------

if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
if "user_data" not in st.session_state:
    st.session_state["user_data"] = None

# ---------------- SIDEBAR NAVIGATION ----------------

with st.sidebar:
    st.markdown("### 🛡️ BharatGuard UPI")
    st.caption("Secure National Payment Network")
    st.divider()

    if st.session_state["logged_in"]:
        st.write(f"👤 **{st.session_state['user_data']['full_name']}**")
        st.write(f"🆔 `{st.session_state['user_data']['upi_id']}`")
        if st.button("🚪 Logout"):
            st.session_state["logged_in"] = False
            st.session_state["user_data"] = None
            st.rerun()
        st.divider()

    page = st.radio(
        "UPI NAVIGATION",
        [
            "💳 Account & Transactions",
            "⚡ Send Money (Automata Secured)",
            "🔍 Message Fraud Inspector",
            "🔑 User Registration & Login"
        ]
    )

# ---------------- HERO HEADER ----------------

st.markdown(f"""
<div class="cyber-hero">
    <div class="cyber-shield-container">
        <img src="{shield_base64}" alt="BharatGuard Shield">
    </div>
    <div class="hero-text">
        <h1>BharatGuard UPI Network</h1>
        <p>Managed Database Banking System with Real-Time Automata Fraud Interception.</p>
    </div>
</div>
""", unsafe_allow_html=True)

# ============================================================
# PAGE 1: ACCOUNT & TRANSACTION HISTORY (DATABASE READ)
# ============================================================

if page == "💳 Account & Transactions":
    st.markdown("### 💳 My UPI Account Dashboard")

    if not st.session_state["logged_in"]:
        st.warning("Please log in or register an account via the 'User Registration & Login' tab to view your dashboard.")
    else:
        conn = get_db_connection()
        user_id = st.session_state["user_data"]["id"]
        user_row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.close()

        col1, col2, col3 = st.columns(3)
        col1.metric("Available Balance", f"₹{user_row['balance']:,.2f}")
        col2.metric("Linked Bank", user_row["bank_name"])
        col3.metric("Account Number", f"•••• {user_row['account_number'][-4:]}")

        st.divider()
        st.markdown("### 📜 Real-Time Database Transaction History")

        conn = get_db_connection()
        user_vpa = user_row["upi_id"]
        txs = conn.execute("""
            SELECT sender_vpa, receiver_vpa, amount, note, status, risk_flag, timestamp 
            FROM transactions 
            WHERE sender_vpa = ? OR receiver_vpa = ?
            ORDER BY timestamp DESC
        """, (user_vpa, user_vpa)).fetchall()
        conn.close()

        if txs:
            tx_data = []
            for tx in txs:
                tx_type = "SENT" if tx["sender_vpa"] == user_vpa else "RECEIVED"
                tx_data.append({
                    "Type": tx_type,
                    "Sender": tx["sender_vpa"],
                    "Receiver": tx["receiver_vpa"],
                    "Amount (₹)": f"₹{tx['amount']:,.2f}",
                    "Remarks / Note": tx["note"],
                    "Status": tx["status"],
                    "Scam Flagged": "🚨 BLOCKED" if tx["risk_flag"] == 1 else "✅ SAFE",
                    "Timestamp": tx["timestamp"]
                })
            st.dataframe(tx_data, use_container_width=True, hide_index=True)
        else:
            st.info("No transaction records found in the database for this account.")

# ============================================================
# PAGE 2: SEND MONEY (DATABASE WRITE + DFA INTERCEPTION)
# ============================================================

elif page == "⚡ Send Money (Automata Secured)":
    st.markdown("### ⚡ Initiate UPI Payment")
    st.write("All transactions pass through our backend database and are scanned in real-time by the Finite State Automata before funds move.")

    if not st.session_state["logged_in"]:
        st.warning("Please log in first to send money.")
    else:
        conn = get_db_connection()
        sender = conn.execute("SELECT * FROM users WHERE id = ?", (st.session_state["user_data"]["id"],)).fetchone()
        conn.close()

        col_form, col_res = st.columns([1.2, 1])

        with col_form:
            st.markdown('<div class="glass-card">', unsafe_allow_html=True)
            st.markdown("#### Payment Portal")
            
            receiver_vpa = st.text_input("Receiver UPI ID (VPA)", placeholder="e.g. merchant@paytm or friend@upi")
            pay_amount = st.number_input("Amount (₹)", min_value=1.0, max_value=50000.0, value=500.0, step=100.0)
            pay_note = st.text_area(
                "Transaction Note / Remarks", 
                value="Urgent update required click link to verify pin",
                height=100,
                placeholder="Enter remarks..."
            )

            submit_pay = st.button("🔒 Process Payment", use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)

        with col_res:
            st.markdown('<div class="glass-card">', unsafe_allow_html=True)
            st.markdown("#### Backend Automata Check")

            if submit_pay:
                if not receiver_vpa.strip():
                    st.warning("Please enter a valid receiver VPA.")
                elif pay_amount > sender["balance"]:
                    st.error("Insufficient account balance!")
                else:
                    analysis = analyze_message(pay_note)
                    
                    conn = get_db_connection()
                    cursor = conn.cursor()

                    if analysis["suspicious"]:
                        cursor.execute("""
                            INSERT INTO transactions (sender_vpa, receiver_vpa, amount, note, status, dfa_state, risk_flag)
                            VALUES (?, ?, ?, ?, ?, ?, 1)
                        """, (sender["upi_id"], receiver_vpa, pay_amount, pay_note, "BLOCKED BY BHARATGUARD", analysis["state"]))
                        conn.commit()
                        conn.close()

                        st.error("🚨 TRANSACTION BLOCKED BY AUTOMATA")
                        st.markdown(f"**Diagnostic:** {analysis['reason']}")
                        st.info(f"**Advice:** {analysis['advice']}")

                    else:
                        new_sender_balance = sender["balance"] - pay_amount
                        cursor.execute("UPDATE users SET balance = ? WHERE id = ?", (new_sender_balance, sender["id"]))
                        
                        cursor.execute("UPDATE users SET balance = balance + ? WHERE upi_id = ?", (pay_amount, receiver_vpa))

                        cursor.execute("""
                            INSERT INTO transactions (sender_vpa, receiver_vpa, amount, note, status, dfa_state, risk_flag)
                            VALUES (?, ?, ?, ?, ?, ?, 0)
                        """, (sender["upi_id"], receiver_vpa, pay_amount, pay_note, "SUCCESS", analysis["state"]))
                        
                        conn.commit()
                        conn.close()

                        st.success("✅ PAYMENT SUCCESSFUL")
                        st.markdown(f"Transferred **₹{pay_amount}** to `{receiver_vpa}`.")
                        st.markdown(f"New Balance: **₹{new_sender_balance:,.2f}**")

            else:
                st.info("Fill in the details and click Process Payment to run database & DFA validation.")
            
            st.markdown('</div>', unsafe_allow_html=True)

# ============================================================
# PAGE 3: MESSAGE FRAUD INSPECTOR
# ============================================================

elif page == "🔍 Message Fraud Inspector":
    st.markdown("### 🔍 Standalone Message & Link Inspector")
    st.write("Test suspicious SMS messages or payment notes against the 16-state bitwise DFA engine.")

    examples = {
        "Select a sample scenario...": "",
        "Urgent Verification Scam (English)": "Your account will be blocked. Click this link immediately to verify your UPI account.",
        "Refund PIN Trap (English)": "Enter your UPI PIN to receive your cashback refund.",
        "Hinglish Phishing Pattern": "Aapka khata turant block ho jayega. Link par click karke UPI pin update kare.",
        "Legitimate Transaction Notice": "You paid 150 rupees to the grocery store. Your transaction was successful."
    }

    selected = st.selectbox("Try a pre-loaded test case", list(examples.keys()))
    message = st.text_area("SMS message payload", value=examples[selected], height=120)

    if st.button("🚀 Run Automata Analysis", use_container_width=True):
        if not message.strip():
            st.warning("Please provide a valid message input.")
        else:
            st.session_state["inspect_result"] = analyze_message(message)

    if "inspect_result" in st.session_state:
        result = st.session_state["inspect_result"]
        
        st.divider()
        col1, col2, col3 = st.columns(3)
        col1.metric("Final DFA State", result["state"])
        col2.metric("Tokens Processed", len(result["words"]))
        col3.metric("Triggers Identified", len(result["indicators"]))

        if result["suspicious"]:
            st.error("🚨 HIGH-RISK FRAUD PATTERN IDENTIFIED")
        else:
            st.success("🛡️ No High-Risk Automata Rules Triggered")

        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        st.markdown("<h4>📈 DFA State Transition Flowchart</h4>", unsafe_allow_html=True)
        graph = generate_state_graph(result["trace"])
        st.graphviz_chart(graph)
        st.markdown('</div>', unsafe_allow_html=True)

# ============================================================
# PAGE 4: USER REGISTRATION & LOGIN (DATABASE AUTH)
# ============================================================

elif page == "🔑 User Registration & Login":
    st.markdown("### 🔑 Database User Portal")

    tab_login, tab_register = st.tabs(["🔒 Login to Account", "📝 Register New UPI Account"])

    with tab_login:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        login_vpa = st.text_input("UPI ID (VPA)", placeholder="e.g. rahul@upi")
        login_pass = st.text_input("Password", type="password")

        if st.button("Login"):
            conn = get_db_connection()
            hashed = hash_password(login_pass)
            user = conn.execute("SELECT * FROM users WHERE upi_id = ? AND password_hash = ?", (login_vpa, hashed)).fetchone()
            conn.close()

            if user:
                st.session_state["logged_in"] = True
                st.session_state["user_data"] = dict(user)
                st.success(f"Welcome back, {user['full_name']}!")
                st.rerun()
            else:
                st.error("Invalid UPI ID or password!")
        st.markdown('</div>', unsafe_allow_html=True)

    with tab_register:
        st.markdown('<div class="glass-card">', unsafe_allow_html=True)
        reg_name = st.text_input("Full Name")
        reg_vpa = st.text_input("Desired UPI ID", placeholder="e.g. yourname@upi")
        reg_pass = st.text_input("Account Password", type="password")
        reg_bank = st.selectbox("Select Bank", ["HDFC Bank", "State Bank of India", "ICICI Bank", "Axis Bank", "Punjab National Bank"])
        reg_acc = st.text_input("Bank Account Number", placeholder="12-digit account number")
        reg_initial_bal = st.number_input("Initial Opening Balance (₹)", min_value=1000.0, value=15000.0)

        if st.button("Create Account"):
            if not (reg_name and reg_vpa and reg_pass and reg_acc):
                st.warning("Please fill in all fields.")
            else:
                conn = get_db_connection()
                try:
                    hashed = hash_password(reg_pass)
                    conn.execute("""
                        INSERT INTO users (full_name, upi_id, password_hash, bank_name, account_number, balance)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (reg_name, reg_vpa, hashed, reg_bank, reg_acc, reg_initial_bal))
                    conn.commit()
                    st.success("Account created successfully! You can now log in.")
                except sqlite3.IntegrityError:
                    st.error("This UPI ID is already registered! Choose a different one.")
                finally:
                    conn.close()
        st.markdown('</div>', unsafe_allow_html=True)

st.divider()
st.caption("BharatGuard • Full-Stack Automata-Based UPI Payment & Security Network")