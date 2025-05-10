import streamlit as st
import socket
import struct
import pickle
from datetime import datetime
from streamlit_autorefresh import st_autorefresh
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# ── RSA Encryption Implementation ────────────────────────────────────────────
class RSAEncryption:
    @staticmethod
    def generate_key_pair():
        # Generate private key (smaller key size for faster demo)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        # Get public key from private key
        public_key = private_key.public_key()
        
        # Serialize keys for storage/transmission
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem

    @staticmethod
    def encrypt_message(msg: str, public_key_pem: bytes) -> bytes:
        # Load the public key
        public_key = serialization.load_pem_public_key(public_key_pem)
        
        # Encrypt data - RSA has size limitations, so we encrypt chunks
        msg_bytes = msg.encode('utf-8')
        
        # RSA with OAEP padding can encrypt data with length:
        # key_size_in_bytes - padding_size
        # For 2048-bit key, that's about 2048/8 - 42 = 214 bytes max
        chunk_size = 190  # Using smaller size to be safe
        encrypted_chunks = []
        
        for i in range(0, len(msg_bytes), chunk_size):
            chunk = msg_bytes[i:i+chunk_size]
            encrypted_chunk = public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_chunks.append(encrypted_chunk)
        
        # Return serialized chunks
        serialized = pickle.dumps(encrypted_chunks)
        return serialized

    @staticmethod
    def decrypt_message(encrypted_data: bytes, private_key_pem: bytes) -> str:
        try:
            # Load the private key
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None
            )
            
            # Deserialize the encrypted chunks
            encrypted_chunks = pickle.loads(encrypted_data)
            
            # Decrypt each chunk
            decrypted_chunks = []
            for chunk in encrypted_chunks:
                decrypted_chunk = private_key.decrypt(
                    chunk,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                decrypted_chunks.append(decrypted_chunk)
            
            # Combine and decode
            return b''.join(decrypted_chunks).decode('utf-8')
        except Exception as e:
            return f"[Decryption error: {str(e)}]"

# ── Configuration ───────────────────────────────────────────────────────────
SERVER_HOST = "localhost"
SERVER_PORT = 12345
BUFFER_SIZE = 8192  # Increased for larger RSA messages

# ── Session State Initialization ─────────────────────────────────────────────
if 'connected' not in st.session_state:
    st.session_state.connected = False
    st.session_state.sock = None
    st.session_state.buffer = b''
    st.session_state.chat_log = []
    st.session_state.username = ""
    st.session_state.private_key = None
    st.session_state.public_key = None
    st.session_state.client_keys = {}  # Store other clients' public keys

# ── Helper to connect ─────────────────────────────────────────────────────────
def connect_to_server(username: str, public_key: bytes):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))
    
    # Send username and public key
    initial_data = {
        'username': username,
        'public_key': public_key
    }
    serialized_data = pickle.dumps(initial_data)
    sock.sendall(serialized_data)
    
    sock.setblocking(False)
    return sock

# ── LOGIN FORM ───────────────────────────────────────────────────────────────
if not st.session_state.connected:
    st.title("🔒 SecureChat (RSA Edition)")
    with st.form("login", clear_on_submit=True):
        uname = st.text_input("Username", key="username_input")
        submitted = st.form_submit_button("Connect")
    
    if submitted and uname:
        try:
            with st.spinner("Generating RSA keys..."):
                # Generate RSA key pair
                private_key, public_key = RSAEncryption.generate_key_pair()
            
            with st.spinner("Connecting to server..."):
                # Connect to server with username and public key
                sock = connect_to_server(uname, public_key)
                
                # Update session state
                st.session_state.username = uname
                st.session_state.private_key = private_key
                st.session_state.public_key = public_key
                st.session_state.sock = sock
                st.session_state.connected = True
                st.session_state.chat_log = []
                
                # Add welcome message
                st.session_state.chat_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Connected to chat server as {uname}")
            
        except Exception as e:
            st.error(f"Connection failed: {e}")
    
    if not st.session_state.connected:
        st.stop()

# ── AUTO‑REFRESH EVERY 2 SECONDS ─────────────────────────────────────────────
_ = st_autorefresh(interval=2000, limit=None, key="auto_refresh")

# ── CHAT INTERFACE ───────────────────────────────────────────────────────────
st.sidebar.markdown(f"**User:** {st.session_state.username}")
st.sidebar.markdown("**Encryption:** RSA 2048-bit")

# Show connected users in sidebar
st.sidebar.markdown("### Connected Users")
for username in st.session_state.client_keys.keys():
    if username != st.session_state.username:
        st.sidebar.markdown(f"- {username}")

st.sidebar.warning("Your keys are generated for this session only.")
st.header("🌍 Secure Chat Room")

# ── 1) Read & buffer incoming bytes, extract framed messages ─────────────────
try:
    while True:
        chunk = st.session_state.sock.recv(BUFFER_SIZE)
        if not chunk:
            break
        st.session_state.buffer += chunk

        # Process all complete frames
        while len(st.session_state.buffer) >= 4:
            msg_len = struct.unpack('!I', st.session_state.buffer[:4])[0]
            if len(st.session_state.buffer) < 4 + msg_len:
                break
            
            packet = st.session_state.buffer[4:4+msg_len]
            st.session_state.buffer = st.session_state.buffer[4+msg_len:]
            
            # Try to deserialize as new protocol
            try:
                # Deserialize the message data
                msg_data = pickle.loads(packet)
                
                # Timestamp
                ts = datetime.now().strftime("%H:%M:%S")
                
                # Handle different message types
                if msg_data['type'] == 'system':
                    text = msg_data['message']
                    st.session_state.chat_log.append(f"[{ts}] {text}")
                
                elif msg_data['type'] == 'client_list':
                    # Update client public key dictionary
                    st.session_state.client_keys = msg_data['clients']
                
                elif msg_data['type'] == 'chat':
                    sender = msg_data['sender']
                    encrypted_message = msg_data['message']
                    
                    # Only decrypt if it's not from ourselves
                    if sender != st.session_state.username:
                        decrypted_text = RSAEncryption.decrypt_message(
                            encrypted_message, 
                            st.session_state.private_key
                        )
                        st.session_state.chat_log.append(f"[{ts}] {sender}: {decrypted_text}")
            
            # Fallback for old protocol format
            except Exception:
                try:
                    # Try to split the old format message
                    parts = packet.split(b"||", 1)
                    if len(parts) == 2:
                        user_bytes, payload = parts
                        user = user_bytes.decode('utf-8', errors='replace')
                        
                        if user == "system":
                            # System message in old format
                            text = payload.decode('utf-8', errors='replace')
                            ts = datetime.now().strftime("%H:%M:%S")
                            st.session_state.chat_log.append(f"[{ts}] {text}")
                        else:
                            # Can't decrypt old format messages as they use different encryption
                            ts = datetime.now().strftime("%H:%M:%S")
                            st.session_state.chat_log.append(
                                f"[{ts}] {user}: [Message encrypted with legacy protocol - cannot decrypt]"
                            )
                except Exception as e:
                    # If all else fails, just log the error
                    ts = datetime.now().strftime("%H:%M:%S")
                    st.session_state.chat_log.append(f"[{ts}] Error processing message: {str(e)}")

except BlockingIOError:
    pass
except Exception as e:
    st.error(f"Receive error: {e}")

# ── 2) Display chat history ─────────────────────────────────────────────────
chat_container = st.container()
with chat_container:
    for line in st.session_state.chat_log:
        st.markdown(f"> {line}")

# ── 3) Message input & send ─────────────────────────────────────────────────
with st.form("send", clear_on_submit=True):
    col1, col2 = st.columns([3, 1])
    
    with col1:
        txt = st.text_input("Message", key="message_input")
    
    with col2:
        recipient_options = ["Everyone"] + [user for user in st.session_state.client_keys.keys() 
                                          if user != st.session_state.username]
        recipient = st.selectbox("To", recipient_options, key="recipient_select")
    
    send = st.form_submit_button("Send")

if send and txt:
    try:
        # Prepare message data
        msg_data = {
            'type': 'chat',
            'sender': st.session_state.username,
            'recipients': [],
            'encrypted_messages': {}
        }
        
        # Encrypt message for each recipient (or everyone)
        if recipient == "Everyone":
            recipients = list(st.session_state.client_keys.keys())
        else:
            recipients = [recipient]
        
        # Add ourselves to recipients to see our own messages
        if st.session_state.username not in recipients:
            recipients.append(st.session_state.username)
            
        # Encrypt for each recipient
        for rcpt in recipients:
            if rcpt in st.session_state.client_keys:
                rcpt_public_key = st.session_state.client_keys[rcpt]
                encrypted_msg = RSAEncryption.encrypt_message(txt, rcpt_public_key)
                msg_data['encrypted_messages'][rcpt] = encrypted_msg
                msg_data['recipients'].append(rcpt)
        
        # Serialize and send
        serialized = pickle.dumps(msg_data)
        length = struct.pack('!I', len(serialized))
        st.session_state.sock.sendall(length + serialized)
        
        # Add to our own chat log
        ts = datetime.now().strftime("%H:%M:%S")
        display_text = f"[{ts}] {st.session_state.username}: {txt}"
        if recipient != "Everyone":
            display_text += f" (to {recipient})"
        st.session_state.chat_log.append(display_text)
        
    except Exception as e:
        st.error(f"Send failed: {e}")