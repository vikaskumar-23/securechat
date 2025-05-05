import streamlit as st
import time
import json
import os
import pickle
import threading
import hashlib

# Files to store messages and user info (no longer storing encryption keys)
MESSAGES_FILE = "chat_messages.pkl"
USERS_FILE = "chat_users.json"

# Set page config to make it look more like a chat app
st.set_page_config(
    page_title="SecureChat",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="expanded"
)

# Custom CSS for Telegram-like UI with fixed header and highlighted active chat
st.markdown("""
<style>
    .main {
        background-color: #17212b;
        color: #fff;
    }
    .stTextInput > div > div > input {
        background-color: #242f3d;
        color: white;
        border-radius: 10px;
    }
    .stButton>button {
        background-color: #5288c1;
        color: white;
        border-radius: 10px;
        border: none;
        padding: 10px 24px;
        font-weight: bold;
    }
    .stButton>button:hover {
        background-color: #6699cc;
    }
    .user-message {
        background-color: #5288c1;
        color: white;
        padding: 10px 15px;
        border-radius: 10px;
        margin: 5px 0;
        max-width: 80%;
        float: right;
        clear: both;
    }
    .other-message {
        background-color: #242f3d;
        color: white;
        padding: 10px 15px;
        border-radius: 10px;
        margin: 5px 0;
        max-width: 80%;
        float: left;
        clear: both;
    }
    .chat-header {
        position: sticky;
        top: 0;
        background-color: #17212b;
        padding: 10px;
        z-index: 999;
        border-bottom: 1px solid #242f3d;
        margin-bottom: 10px;
    }
    .message-container {
        overflow-y: auto;
        height: 400px;
        padding: 10px;
        background-color: #17212b;
        margin-top: 10px;
    }
    .username {
        font-size: 12px;
        color: #aaa;
        margin-bottom: 2px;
    }
    .timestamp {
        font-size: 10px;
        color: #aaa;
        text-align: right;
    }
    .sidebar .sidebar-content {
        background-color: #242f3d;
    }
    h1, h2, h3 {
        color: #fff;
    }
    .active-chat {
        background-color: #3a5070 !important;
        border-left: 3px solid #5288c1 !important;
    }
    /* Make chat buttons fill width in sidebar */
    .stButton>button[data-baseweb="button"] {
        width: 100%;
        text-align: left;
    }
    /* Ensure the chat header stays fixed at the top of the viewport */
    div.chat-header {
        position: sticky;
        top: 0;
        background-color: #17212b;
        z-index: 9999;
        padding: 10px;
        margin-bottom: 15px;
        border-bottom: 1px solid #242f3d;
    }
    /* Custom styling for active chat button */
    button.active-chat-button {
        background-color: #3a5070 !important;
        border-left: 3px solid #5288c1 !important;
    }
</style>
""", unsafe_allow_html=True)

# Locks for thread-safe file operations
message_lock = threading.Lock()
user_lock = threading.Lock()

# Custom encryption/decryption with improved security
class CustomEncryption:
    @staticmethod
    def get_shift_value(key):
        key = int(key)
        shift = key % 26
        return shift
    
    @staticmethod
    def encrypt_message(message, key):
        shift = CustomEncryption.get_shift_value(key)
        encrypted_chars = []
        
        for char in message:
            # Shift the ASCII value
            char_code = ord(char)
            encrypted_char_code = char_code + shift
            encrypted_chars.append(chr(encrypted_char_code))
        
        # Add a verification hash based on the key to verify correct decryption later
        key_hash = hashlib.md5(str(shift).encode()).hexdigest()[:8]
        encrypted_message = ''.join(encrypted_chars)
        
        # Return the encrypted message with key verification hash
        return f"{encrypted_message}||{key_hash}"
    
    @staticmethod
    def decrypt_message(encrypted_data, key):
        # Split the message and verification hash
        try:
            encrypted_message, key_hash = encrypted_data.split("||")
        except ValueError:
            # If the format is invalid, decryption is not possible
            return "[Encrypted message - Cannot decrypt]"
        
        # Verify the key is correct by checking the hash
        shift = CustomEncryption.get_shift_value(key)
        expected_hash = hashlib.md5(str(shift).encode()).hexdigest()[:8]
        if key_hash != expected_hash:
            return "[Encrypted message - Wrong decryption key]"
        
        decrypted_chars = []
        
        for char in encrypted_message:
            # Reverse the shift
            char_code = ord(char)
            decrypted_char_code = char_code - shift
            decrypted_chars.append(chr(decrypted_char_code))
        
        return ''.join(decrypted_chars)

# File operations
def save_messages(messages_dict):
    with message_lock:
        with open(MESSAGES_FILE, 'wb') as f:
            pickle.dump(messages_dict, f)

def load_messages():
    with message_lock:
        if os.path.exists(MESSAGES_FILE):
            try:
                with open(MESSAGES_FILE, 'rb') as f:
                    return pickle.load(f)
            except Exception as e:
                st.error(f"Error loading messages: {e}")
                return {}
        return {}

# Modified: Now only stores usernames, not encryption keys
def save_user(username):
    with user_lock:
        user_data = []
        if os.path.exists(USERS_FILE):
            try:
                with open(USERS_FILE, 'r') as f:
                    user_data = json.load(f)
            except:
                user_data = []
        
        # Store just the username, not the key
        if username not in user_data:
            user_data.append(username)
        
        with open(USERS_FILE, 'w') as f:
            json.dump(user_data, f)

def delete_user(username):
    with user_lock:
        if os.path.exists(USERS_FILE):
            try:
                with open(USERS_FILE, 'r') as f:
                    user_data = json.load(f)
                
                # Remove the user if they exist
                if username in user_data:
                    user_data.remove(username)
                
                with open(USERS_FILE, 'w') as f:
                    json.dump(user_data, f)
                    
                return True
            except Exception as e:
                st.error(f"Error deleting user: {e}")
        return False

def get_all_users():
    with user_lock:
        if os.path.exists(USERS_FILE):
            try:
                with open(USERS_FILE, 'r') as f:
                    return json.load(f)
            except Exception as e:
                st.error(f"Error loading users: {e}")
                return []
        return []

# Function to generate a conversation ID between two users
def get_conversation_id(user1, user2):
    # Sort usernames to ensure the same ID regardless of order
    users = sorted([user1, user2])
    return f"{users[0]}_{users[1]}"

# Remove user data from conversations
def clean_user_from_conversations(username):
    all_messages = load_messages()
    
    # For each conversation, add a system message that the user has left
    for conv_id, messages in all_messages.items():
        # Only add the system message if this user was part of the conversation
        if conv_id == "general" or username in conv_id.split("_"):
            system_message = {
                "sender": "system",
                "message": f"{username} has left the chat",
                "timestamp": time.strftime("%H:%M"),
                "encrypted": False
            }
            all_messages[conv_id].append(system_message)
    
    save_messages(all_messages)

# Initialize session state variables
if 'username' not in st.session_state:
    st.session_state.username = ""

if 'encryption_key' not in st.session_state:
    st.session_state.encryption_key = None

if 'current_chat' not in st.session_state:
    st.session_state.current_chat = "general"

if 'last_message_check' not in st.session_state:
    st.session_state.last_message_check = time.time()

if 'chat_list' not in st.session_state:
    st.session_state.chat_list = ["general"]

# Initialize or load messages
if 'messages_loaded' not in st.session_state:
    all_messages = load_messages()
    if not all_messages:
        all_messages = {"general": []}
    st.session_state.all_messages = all_messages
    st.session_state.messages_loaded = True

# Login screen
def login_screen():
    st.markdown("<h1 style='text-align: center; color: #5288c1;'>🔒 SecureChat</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center;'>Encrypted messaging for private conversations</p>", unsafe_allow_html=True)
    
    with st.form("login_form", clear_on_submit=True):
        username = st.text_input("Username", key="username_input")
        encryption_key = st.text_input("Encryption Key (Integer)", key="key_input", 
                                    help="This key will be used for encryption. Keep it secret and don't share it with anyone.")
        
        # Get list of users for the new user to chat with
        existing_users = get_all_users()
        if existing_users:
            st.write("Available users to chat with:")
            for user in existing_users:
                st.write(f"- {user}")
        
        submitted = st.form_submit_button("Join Chat")
        
        if submitted and username and encryption_key:
            try:
                # Validate that encryption key is an integer
                encryption_key = int(encryption_key)
                
                # Save only the username to the list of users, NOT THE KEY
                save_user(username)
                
                st.session_state.username = username
                st.session_state.encryption_key = encryption_key
                
                # Build chat list - general chat plus individual users
                users = get_all_users()
                chat_list = ["general"]
                for user in users:
                    if user != username:  # Don't chat with yourself
                        chat_list.append(user)
                
                st.session_state.chat_list = chat_list
                st.session_state.current_chat = "general"
                
                # Initialize general chat if not exists
                if "general" not in st.session_state.all_messages:
                    st.session_state.all_messages["general"] = []
                    save_messages(st.session_state.all_messages)
                
                # Add system message
                system_message = {
                    "sender": "system",
                    "message": f"{username} has joined the chat",
                    "timestamp": time.strftime("%H:%M"),
                    "encrypted": False
                }
                st.session_state.all_messages["general"].append(system_message)
                save_messages(st.session_state.all_messages)
                
                st.rerun()
                
            except ValueError:
                st.error("Encryption key must be an integer.")

# Message polling function
def check_for_new_messages():
    # Load messages from storage
    current_messages = load_messages()
    
    # Update session state with new messages
    if current_messages:
        st.session_state.all_messages = current_messages
    
    # Update last check time
    st.session_state.last_message_check = time.time()
    
    # Refresh chat list with any new users
    users = get_all_users()
    chat_list = ["general"]
    for user in users:
        if user != st.session_state.username:  # Don't chat with yourself
            chat_list.append(user)
    
    st.session_state.chat_list = chat_list

# Validate message structure
def is_valid_message(msg):
    # Check if msg is a dictionary and has the required keys
    return (isinstance(msg, dict) and 
            "sender" in msg and 
            "message" in msg and 
            "timestamp" in msg)

# Main chat interface
def chat_interface():
    # Check for new messages every few seconds
    if time.time() - st.session_state.last_message_check > 2:
        check_for_new_messages()
    
    # Sidebar for chat selection and user info
    with st.sidebar:
        st.markdown(f"<h3>👤 {st.session_state.username}</h3>", unsafe_allow_html=True)
        st.markdown(f"<p>Your encryption key: {st.session_state.encryption_key}</p>", unsafe_allow_html=True)
        st.warning("Keep your encryption key private! Never share it with anyone.")
        
        # Add refresh button to the sidebar
        if st.button("↻ Refresh Messages", key="sidebar_refresh"):
            check_for_new_messages()
            st.rerun()
        
        st.markdown("### 💬 Your Chats")
        
        # Display chat list with active chat highlighted
        for chat in st.session_state.chat_list:
            if chat == "general":
                chat_display = "🌍 General (Public)"
            else:
                chat_display = f"👤 {chat} (Encrypted)"
            
            # Apply active class for the current chat
            is_active = chat == st.session_state.current_chat
            
            # Create a button with conditional styling based on active status
            if is_active:
                # Apply active styling directly to the button using markdown
                st.markdown(
                    f"""
                    <button class="stButton active-chat-button" 
                            style="width: 100%; text-align: left; background-color: #3a5070; 
                                   border-left: 3px solid #5288c1; color: white; 
                                   border-radius: 10px; padding: 10px 24px; font-weight: bold;"
                            disabled>
                        {chat_display}
                    </button>
                    """, 
                    unsafe_allow_html=True
                )
            else:
                # Regular button for non-active chats
                if st.button(
                    chat_display, 
                    key=f"chat_{chat}", 
                    help=f"Switch to {chat} chat",
                    on_click=lambda c=chat: setattr(st.session_state, 'current_chat', c)
                ):
                    pass  # Logic handled by on_click
        
        if st.button("Logout"):
            username_to_delete = st.session_state.username
            
            # Clean up user data and add system message
            clean_user_from_conversations(username_to_delete)
            
            # Delete the user from users file
            delete_user(username_to_delete)
            
            # Clear session state
            for key in list(st.session_state.keys()):
                if key != 'all_messages' and key != 'messages_loaded':
                    del st.session_state[key]
            
            st.rerun()
    
    # Main chat area
    current_chat = st.session_state.current_chat
    is_private = current_chat != "general"
    
    # Fixed header with chat information - made more visible and definitely fixed
    st.markdown(
        f"""
        <div class="chat-header">
            <h2>{"🔒 Private Chat with " + current_chat if is_private else "🌍 General Chat"}</h2>
            <p>{
                "This chat is encrypted with your personal key. Messages can only be decrypted if the recipient has the same key as you." 
                if is_private else 
                "The general channel is public. Messages are not encrypted."
            }</p>
        </div>
        """, 
        unsafe_allow_html=True
    )
    
    # Set up conversation ID for private chats
    conversation_id = current_chat
    if is_private:
        conversation_id = get_conversation_id(st.session_state.username, current_chat)
    
    # Initialize conversation if not exists
    if conversation_id not in st.session_state.all_messages:
        st.session_state.all_messages[conversation_id] = []
        save_messages(st.session_state.all_messages)
    
    # Message display container - scrollable area
    message_container = st.container()
    with message_container:
        # Display messages - with error handling for malformed messages
        for msg in st.session_state.all_messages[conversation_id]:
            # Check if message has valid structure
            if not is_valid_message(msg):
                st.markdown("""
                <div style="text-align: center; margin: 10px 0; color: #ff6b6b; clear: both;">
                    Found a corrupted message. It has been skipped.
                </div>
                """, unsafe_allow_html=True)
                continue
                
            is_self = msg["sender"] == st.session_state.username
            is_system = msg["sender"] == "system"
            
            if is_system:
                st.markdown(f"""
                <div style="text-align: center; margin: 10px 0; color: #aaa; clear: both;">
                    {msg["message"]}
                </div>
                """, unsafe_allow_html=True)
            else:
                # Handle message display based on encryption status
                display_message = msg["message"]
                
                # If message is encrypted, handle it properly
                if msg.get("encrypted", False):
                    if is_self:
                        # If I sent the message, show my original text
                        if "original_message" in msg:
                            display_message = msg["original_message"]
                        else:
                            # Fallback if original message is not stored
                            display_message = "[Your encrypted message]"
                    else:
                        # Try to decrypt with my key
                        try:
                            display_message = CustomEncryption.decrypt_message(display_message, st.session_state.encryption_key)
                        except Exception as e:
                            display_message = f"[Encrypted message - Error: {str(e)}]"
                
                st.markdown(f"""
                <div style="width: 100%; overflow: hidden; margin-bottom: 10px; clear: both;">
                    <div class="{'user-message' if is_self else 'other-message'}">
                        <div class="username">{msg["sender"]}</div>
                        {display_message}
                        <div class="timestamp">{msg["timestamp"]}</div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
    
    # Message input
    with st.form("message_form", clear_on_submit=True):
        col1, col2 = st.columns([5, 1])
        with col1:
            message = st.text_input("Message", placeholder="Type a message...", label_visibility="collapsed")
        with col2:
            submitted = st.form_submit_button("Send")
        
        if submitted and message:
            # Prepare new message
            encrypted = is_private
            original_message = message  # Store original message for the sender to see
            
            if encrypted:
                # For private messages, encrypt with YOUR OWN key (not the recipient's)
                try:
                    encrypted_message = CustomEncryption.encrypt_message(message, st.session_state.encryption_key)
                except Exception as e:
                    st.error(f"Encryption error: {str(e)}")
                    encrypted_message = message
                    encrypted = False
            else:
                encrypted_message = message
            
            new_message = {
                "sender": st.session_state.username,
                "message": encrypted_message,
                "timestamp": time.strftime("%H:%M"),
                "encrypted": encrypted
            }
            
            # Store the original message so the sender can see what they typed
            if encrypted:
                new_message["original_message"] = original_message
            
            # Add message to the current conversation
            st.session_state.all_messages[conversation_id].append(new_message)
            save_messages(st.session_state.all_messages)
            st.rerun()

# Main app logic
def main():
    if not st.session_state.username:
        login_screen()
    else:
        chat_interface()

if __name__ == "__main__":
    main()