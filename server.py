import socket
import threading
import struct
import pickle
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

HOST = '0.0.0.0'
PORT = 12345
MAX_BUFFER = 8192  # Increased for handling RSA encrypted messages

# Client info storage
clients = []  # (connection, username, public_key)
clients_lock = threading.Lock()

def send_framed(conn: socket.socket, data: bytes):
    """Send length-prefixed data to a client."""
    length = struct.pack('!I', len(data))
    conn.sendall(length + data)

def broadcast_client_list():
    """Send updated client list to all connected clients."""
    with clients_lock:
        # Create a dictionary of {username: public_key} for all clients
        client_dict = {username: public_key for _, username, public_key in clients}
        
        # Create message data
        msg_data = {
            'type': 'client_list',
            'clients': client_dict
        }
        
        # Serialize and broadcast
        serialized = pickle.dumps(msg_data)
        for conn, _, _ in clients:
            try:
                send_framed(conn, serialized)
            except Exception as e:
                logger.error(f"Failed to send client list: {e}")

def broadcast_system_message(message: str):
    """Send system message to all clients."""
    msg_data = {
        'type': 'system',
        'message': message
    }
    serialized = pickle.dumps(msg_data)
    
    with clients_lock:
        for conn, _, _ in clients:
            try:
                send_framed(conn, serialized)
            except Exception as e:
                logger.error(f"Failed to send system message: {e}")

def handle_client(conn: socket.socket, addr):
    """Handle client connection and messages."""
    username = None
    public_key = None
    
    try:
        # Receive initial connection data
        initial_data_raw = conn.recv(MAX_BUFFER)
        if not initial_data_raw:
            logger.warning(f"Empty initial data from {addr}")
            return
        
        # Deserialize the initial data
        try:
            initial_data = pickle.loads(initial_data_raw)
            username = initial_data['username']
            public_key = initial_data['public_key']
        except Exception as e:
            logger.error(f"Failed to parse initial data: {e}")
            return
        
        logger.info(f"Client connected: {username} from {addr}")
        
        # Add client to list
        with clients_lock:
            clients.append((conn, username, public_key))
        
        # Broadcast join message
        join_msg = f"** {username} has joined the chat **"
        broadcast_system_message(join_msg)
        
        # Send updated client list to everyone
        broadcast_client_list()
        
        # Main message loop
        while True:
            # Read message length
            length_bytes = conn.recv(4)
            if not length_bytes or len(length_bytes) < 4:
                break
            
            msg_len = struct.unpack('!I', length_bytes)[0]
            
            # Read full message
            data = b''
            while len(data) < msg_len:
                chunk = conn.recv(min(MAX_BUFFER, msg_len - len(data)))
                if not chunk:
                    raise ConnectionError("Connection closed while receiving data")
                data += chunk
            
            if not data:
                break
                
            # Process the message
            try:
                msg_data = pickle.loads(data)
                
                # Handle chat message
                if msg_data['type'] == 'chat':
                    sender = msg_data['sender']
                    recipients = msg_data['recipients']
                    encrypted_messages = msg_data['encrypted_messages']
                    
                    with clients_lock:
                        # For each recipient, send the message encrypted with their public key
                        for recipient_name in recipients:
                            recipient_conns = [c for c, u, _ in clients if u == recipient_name]
                            if recipient_conns:
                                recipient_conn = recipient_conns[0]
                                
                                # Create a message specific for this recipient
                                forwarded_msg = {
                                    'type': 'chat',
                                    'sender': sender,
                                    'message': encrypted_messages[recipient_name]
                                }
                                
                                # Serialize and send
                                serialized = pickle.dumps(forwarded_msg)
                                send_framed(recipient_conn, serialized)
            except Exception as e:
                logger.error(f"Error processing message: {e}")
    
    except ConnectionResetError:
        logger.info(f"Connection reset by {username or addr}")
    except ConnectionError as e:
        logger.info(f"Connection error with {username or addr}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error with client {username or addr}: {e}")
    finally:
        # Remove client from list
        with clients_lock:
            clients[:] = [(c, u, k) for c, u, k in clients if c is not conn]
        
        # Close connection
        try:
            conn.close()
        except:
            pass
        
        # If client was authenticated, broadcast departure
        if username:
            logger.info(f"Client disconnected: {username}")
            leave_msg = f"** {username} has left the chat **"
            broadcast_system_message(leave_msg)
            
            # Send updated client list
            broadcast_client_list()

def main():
    """Main server function."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((HOST, PORT))
        server.listen(5)
        logger.info(f"Server listening on {HOST}:{PORT}")
        
        while True:
            conn, addr = server.accept()
            logger.info(f"New connection from {addr}")
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
            
    except KeyboardInterrupt:
        logger.info("Server shutting down")
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        server.close()

if __name__ == "__main__":
    main()