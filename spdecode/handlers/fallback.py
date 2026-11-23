from __future__ import annotations

import base64
import json

from Crypto.Cipher import AES

from spdecode.access import require_authorized
from spdecode.handlers.results import send_markdown_result
from spdecode.runtime import bot

BASE64_KEY = "X25ldHN5bmFfbmV0bW9kXw=="
DECRYPTION_KEY = base64.b64decode(BASE64_KEY)

def decrypt_aes_ecb_128(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.rstrip()

def format_common_data(common_data):
    formatted_text = ""
    for entry in common_data:
        for key, value in entry.items():
            formatted_text += f"│[۞] {key}: {value}\n"
    return formatted_text

def format_result(data):
    result = ""
    for key, value in data.items():
        if key == "Common":
            result += f"│[۞] {key}:\n{format_common_data(value)}"
        else:
            result += f"│[۞] {key}: {value}\n"
    return result or "{}"

def process_encrypted_content(encrypted_content):
    try:
        ciphertext = base64.b64decode(encrypted_content)
        decrypted_text = decrypt_aes_ecb_128(ciphertext, DECRYPTION_KEY)
        formatted_text = decrypted_text.decode('utf-8')
        start_index = formatted_text.find("{")
        end_index = formatted_text.rfind("}")

        if start_index == -1 or end_index == -1 or end_index < start_index:
            return None

        json_text = formatted_text[start_index:end_index + 1]
        data = json.loads(json_text)
        return format_result(data)
    except Exception as e:
        return None  
        
@bot.message_handler(func=lambda message: getattr(message, "text", None) is not None)
@require_authorized("Los textos cifrados")
def handle_message(message):
    encrypted_content = message.text.strip()
    try:
        response = process_encrypted_content(encrypted_content)
        if response:
            send_markdown_result(message, "NetMod Syna", response)
            return
    except Exception as e:
        print(f"Error al manejar el mensaje: {e}")
    fallback_processing(message)

def fallback_processing(message):
    try:
        pass 
    except Exception as e:
        print(f"Error en fallback_processing: {e}")
                        
########################################        
