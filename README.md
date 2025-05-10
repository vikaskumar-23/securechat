# SecureChat (RSA Edition)

A simple encrypted chat application built with Python sockets and Streamlit, upgraded to use RSA public-key encryption for end-to-end secure messaging between clients connected to a central server.

---

## 🗒️ Features

* **Server (`server.py`)**: Manages client connections and broadcasts framed messages to participants.
* **Client (`streamlit_app.py`)**: Streamlit-based UI for real-time chat with auto-refresh.
* **RSA Encryption**: 2048-bit asymmetric encryption with OAEP padding. Each message is encrypted per recipient using their public key and decrypted with the recipient's private key.
* **Dynamic Client List**: Server tracks connected users and their public keys; clients receive updates in real time.
* **Auto-Refresh**: Chat interface polls for new messages every 2 seconds.

---

## 🛠️ Prerequisites

* Python 3.7 or newer
* **pip** package manager

---

## ⚙️ Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/<your-username>/SecureChat.git
   cd SecureChat
   ```
2. **Install dependencies**:

   ```bash
   pip install streamlit streamlit-autorefresh cryptography
   ```

---

## ⚙️ Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/<your-username>/SecureChat.git
   cd SecureChat
   ```

2. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

   > **requirements.txt** should include:
   >
   > ```
   > streamlit
   > streamlit-autorefresh
   > cryptography
   > ```

---

## 🔧 Configuration

* **Server**:

  * Default host: `0.0.0.0`
  * Default port: `12345`
  * To change, edit the `HOST` and `PORT` constants in `server.py`.

* **Client** (`streamlit_app.py`):

  * Default server: `localhost:12345`
  * To change, update `SERVER_HOST` and `SERVER_PORT` constants.

---

## 🚀 Usage

1. **Start the server**:

   ```bash
   python server.py
   ```

   You should see:

   ```
   INFO:__main__:Server listening on 0.0.0.0:12345
   ```

2. **Run the client**:

   ```bash
   streamlit run streamlit_app.py
   ```

3. **Connect**:

   * In the Streamlit UI, enter a **username**.
   * Click **Connect**. An RSA key pair (private & public) will be generated client‑side.

4. **Chat**:

   * Select a recipient ("Everyone" or a specific user).
   * Type a message and hit **Send**.
   * The message is encrypted with each recipient's public key and delivered securely.
   * Incoming encrypted messages are decrypted with your private key and displayed.

---

## 🔐 Encryption Details

1. **Key Generation**:

   ```python
   private_key = rsa.generate_private_key(
       public_exponent=65537,
       key_size=2048
   )
   public_key = private_key.public_key()
   ```

2. **Serialization**:

   * **Private PEM** stored in session state (no password).
   * **Public PEM** sent to server to distribute among clients.

3. **Encryption**:

   * Messages are chunked (≤190 bytes) due to RSA size limits.
   * Each chunk encrypted with recipient's public key using OAEP padding:

     ```python
     encrypted = public_key.encrypt(
         chunk,
         padding.OAEP(
             mgf=padding.MGF1(algorithm=hashes.SHA256()),
             algorithm=hashes.SHA256(),
             label=None
         )
     )
     ```
   * Chunks serialized via `pickle` before network transmission.

4. **Decryption**:

   * Serialized chunks are deserialized with `pickle`.
   * Each chunk is decrypted using the private key:

     ```python
     plaintext_chunk = private_key.decrypt(
         chunk,
         padding.OAEP(
             mgf=padding.MGF1(algorithm=hashes.SHA256()),
             algorithm=hashes.SHA256(),
             label=None
         )
     )
     ```

---

## 📂 File Overview

* **`server.py`**: Central chat server handling connections, broadcasting system messages, client-list updates, and relaying encrypted chat packets.
* **`streamlit_app.py`**: Streamlit client UI with:

  * RSA key generation & serialization
  * Framed TCP communication
  * Message chunking, encryption, and decryption logic
  * Auto-refresh for incoming messages

---

## 📝 Notes

* **Session Keys**: RSA keys are ephemeral and valid only per client session; refreshing the page generates a new pair.
* **Performance**: RSA chunking adds overhead; recommended for moderate chat volumes or demo purposes.
* **Extensibility**: Can integrate hybrid encryption (e.g., AES session keys) to improve performance.

Enjoy secure, end-to-end encrypted chatting!
