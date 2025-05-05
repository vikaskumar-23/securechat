# SecureChat

SecureChat is a Streamlit-based encrypted messaging application modeled after Telegram’s UI. It allows users to join a public “general” chat or have encrypted one-on-one conversations using a simple shift-based encryption scheme.

## Features

* Public general chat (unencrypted)
* Private one-on-one chats with end-to-end encryption using a shift cipher and MD5-based key hash verification
* User registration and login with integer encryption keys (keys are never stored)
* Thread-safe file-based storage for messages and user list (using pickle and JSON)
* Telegram-like UI with sticky headers, message bubbles, and sidebar chat list

## Prerequisites

* Python 3.7 or newer
* A terminal or command prompt

## Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/yourusername/securechat.git
   cd securechat
   $1├── README.md           # This file
   ```

2. **(Optional) Create and activate a virtual environment**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\\Scripts\\activate
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

## requirements.txt

Make sure your `requirements.txt` includes at least:

```
streamlit
```

Additional libraries included in the code are part of the Python standard library.

## Running the App

From the project root directory, run:

```bash
streamlit run app.py
```

Replace `app.py` with the main Python file if you named it differently.

Once the server starts, open the provided local URL (usually [http://localhost:8501](http://localhost:8501)) in your browser.

## Usage

1. **Join the chat**: Enter a unique username and an integer encryption key. Keep your key secret.
2. **General Chat**: By default, you join the public “general” chat—messages here are unencrypted.
3. **Private Chat**: Select another user from the sidebar to start a private encrypted chat. Both users must use the same integer key to decrypt messages.
4. **Send Messages**: Type in the input box and hit “Send.”
5. **Refresh**: Use the sidebar “Refresh Messages” button or wait for the auto-polling.
6. **Logout**: Click “Logout” to remove yourself and notify other users.

## File Structure

```
securechat/
├── app.py              # Main Streamlit application
├── chat_messages.pkl   # Pickle file storing chat history
├── chat_users.json     # JSON file storing registered usernames
├── requirements.txt    # Python package requirements
└── README.md           # This file
```

# Thank You!