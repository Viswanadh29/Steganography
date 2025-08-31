import os
import hashlib
import base64
from flask import Flask, request, render_template, jsonify
import cv2
import numpy as np
from cryptography.fernet import Fernet

# Initialize the Flask application
app = Flask(__name__)

# --- Helper Functions ---


def hash_password(password):
    """Returns a SHA-256 hash of the given password."""
    return hashlib.sha256(password.encode()).hexdigest()


def derive_key(password: str) -> bytes:
    """Derives a Fernet key from the password using SHA256."""
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())


def get_image_capacity(img_data):
    """Calculates the maximum number of characters that can be hidden in an image."""
    img = cv2.imdecode(np.frombuffer(img_data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        return 0
    total_pixels = img.shape[0] * img.shape[1] * 3
    return total_pixels // 8


def encode_image(img_data, secret_msg, password):
    """Encodes an encrypted secret message into an image using LSB steganography."""
    img = cv2.imdecode(np.frombuffer(img_data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError(
            "Could not read image data. Please use a valid image file.")

    # 🔒 Encrypt the message
    key = derive_key(password)
    fernet = Fernet(key)
    encrypted_msg = fernet.encrypt(secret_msg.encode("utf-8"))

    # Base64 encode encrypted message to make it safe for embedding
    encrypted_b64 = base64.urlsafe_b64encode(encrypted_msg).decode("utf-8")

    # Store hash + encrypted message + end marker
    hashed_pwd = hash_password(password)
    full_msg = f"{hashed_pwd}|{encrypted_b64}###END###".encode("utf-8")

    # Convert the full message to bits
    msg_bits = ''.join([format(byte, '08b') for byte in full_msg])
    bit_idx = 0

    # Check capacity
    capacity_bits = img.shape[0] * img.shape[1] * 3
    if len(msg_bits) > capacity_bits:
        raise ValueError(
            f"Message is too long for this image! Max capacity is {capacity_bits // 8} bytes.")

    # Embed bits into image
    for row in img:
        for pixel in row:
            for channel in range(3):
                if bit_idx < len(msg_bits):
                    pixel[channel] = (pixel[channel] & 0b11111110) | int(
                        msg_bits[bit_idx])
                    bit_idx += 1
                else:
                    break
            if bit_idx >= len(msg_bits):
                break
        if bit_idx >= len(msg_bits):
            break

    # Encode back to PNG
    is_success, buffer = cv2.imencode(".png", img)
    if not is_success:
        raise Exception(
            "Could not encode image for sending. Please try again.")

    return base64.b64encode(buffer).decode('utf-8')


def decode_image(img_data, password):
    """Decodes and decrypts a secret message from a stego-image."""
    img = cv2.imdecode(np.frombuffer(img_data, np.uint8), cv2.IMREAD_COLOR)
    if img is None:
        raise ValueError("Could not read image data. Is it a valid image?")

    binary_data = ""
    extracted_bytes = bytearray()
    found = False

    # Extract LSBs
    for row in img:
        for pixel in row:
            for channel in range(3):
                binary_data += str(pixel[channel] & 1)
                if len(binary_data) % 8 == 0:
                    extracted_bytes.append(int(binary_data[-8:], 2))
                    if extracted_bytes.endswith(b"###END###"):
                        found = True
                        break
            if found:
                break
        if found:
            break

    if not found:
        return "❌ No hidden message found in this image."

    try:
        extracted_text = extracted_bytes.replace(
            b"###END###", b"").decode("utf-8", errors="ignore")
        stored_hash, encrypted_b64 = extracted_text.split("|", 1)

        # Verify password
        if hash_password(password) != stored_hash:
            return "❌ Wrong Password! Please try again."

        # Convert back from base64 and decrypt
        encrypted_msg = base64.urlsafe_b64decode(encrypted_b64.encode("utf-8"))
        key = derive_key(password)
        fernet = Fernet(key)
        secret_msg = fernet.decrypt(encrypted_msg).decode("utf-8")

        return secret_msg
    except Exception as e:
        return f"❌ Failed to decode or decrypt: {e}"


# --- Flask Routes ---


@app.route('/', methods=['GET', 'POST'])
def index():
    status_message = None
    warning_message = None
    encoded_image = None
    decoded_message = None
    image_capacity = None

    active_tab = request.args.get('tab', 'encode')

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'encode':
            active_tab = 'encode'
            if 'image' not in request.files or not request.files['image'].filename:
                status_message = "❌ Error: Please provide an image, a message, and a password."
            else:
                try:
                    file = request.files['image']
                    if os.path.splitext(file.filename)[1].lower() in ['.jpg', '.jpeg']:
                        warning_message = "⚠️ Warning: JPEG is a lossy format. Use PNG for best results."

                    img_data = file.read()
                    image_capacity = get_image_capacity(img_data)

                    secret_msg = request.form.get('message', '')
                    password = request.form.get('password', '')

                    if not secret_msg or not password:
                        status_message = "❌ Error: Please provide an image, a message, and a password."
                    else:
                        encoded_image = encode_image(
                            img_data, secret_msg, password)
                        status_message = "✅ Message encoded successfully! You can now download the new image."

                except ValueError as e:
                    status_message = f"❌ Error: {e}"
                except Exception as e:
                    status_message = f"❌ An unexpected error occurred: {e}"

        elif action == 'decode':
            active_tab = 'decode'
            if 'image' not in request.files or not request.form.get('password'):
                status_message = "❌ Error: Please provide both an image and a password."
            else:
                try:
                    img_data = request.files['image'].read()
                    password = request.form['password']

                    decoded_message = decode_image(img_data, password)
                    if not decoded_message.startswith("❌"):
                        status_message = "✅ Message decoded successfully!"
                    else:
                        status_message = decoded_message
                        decoded_message = None
                except ValueError as e:
                    status_message = f"❌ Error: {e}"
                except Exception as e:
                    status_message = f"❌ An unexpected error occurred: {e}"

    return render_template('index.html',
                           status=status_message,
                           warning=warning_message,
                           encoded_image=encoded_image,
                           decoded_message=decoded_message,
                           active_tab=active_tab,
                           image_capacity=image_capacity)


@app.route('/calculate_capacity', methods=['POST'])
def calculate_capacity():
    if 'image' not in request.files:
        return jsonify({'error': 'No image file provided'}), 400

    file = request.files['image']
    img_data = file.read()

    try:
        capacity = get_image_capacity(img_data)
        return jsonify({'capacity': capacity})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
