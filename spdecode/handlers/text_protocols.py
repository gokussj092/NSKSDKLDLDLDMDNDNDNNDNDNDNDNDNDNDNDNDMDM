from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import urllib.parse
from base64 import b64decode
from urllib.parse import parse_qs, urlparse

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from decoders.Python.DARKTUNNEL import run as decode_dark_payload
from decoders.Python.SSCCUSTOM import run as decode_ssc_payload
from decoders.Python.TLS import run as decode_tls_payload
from spdecode.access import require_authorized
from spdecode.handlers.results import send_markdown_result
from spdecode.runtime import bot, settings
from spdecode.text_sessions import (
    append_to_session,
    cleanup_expired,
    clear_session,
    get_session,
    start_session,
)
from spdecode.utils import html_pre

logger = logging.getLogger("sp-decode")


def _message_text(message) -> str:
    return getattr(message, "text", None) or ""


# ---------------------------------------------------------------------------
# TLS Tunnel por texto
# ---------------------------------------------------------------------------
_TLS_START_RE = re.compile(r"(?i)(?<![A-Za-z0-9._-])tls://(?P<payload>[^\s`]+)")


def _extract_tls_text(text: str) -> str | None:
    match = _TLS_START_RE.search(text.replace("\ufeff", ""))
    if match is None:
        return None
    payload = match.group("payload").strip()
    return f"tls://{payload}" if payload else None


def _is_tls_text_message(message) -> bool:
    return _extract_tls_text(_message_text(message)) is not None


@bot.message_handler(func=_is_tls_text_message)
@require_authorized("TLS Tunnel text")
def decode_tls_text(message):
    """Descifra enlaces tls:// completos usando el mismo motor que los archivos .tls."""
    payload = _extract_tls_text(_message_text(message))
    if payload is None:
        return

    try:
        result = decode_tls_payload(payload.encode("utf-8"))
    except Exception:
        logger.exception("Internal error decoding TLS Tunnel text")
        bot.reply_to(
            message,
            "<b>Could not process TLS Tunnel</b>\n"
            "The decoder reported an internal error.",
            parse_mode="HTML",
        )
        return

    if result:
        send_markdown_result(message, "TLS Tunnel", result)
    else:
        bot.reply_to(
            message,
            "<b>Could not decode TLS Tunnel</b>\n"
            "The text does not match a supported encryption format.",
            parse_mode="HTML",
        )


# ---------------------------------------------------------------------------
# Mensajes multipart: SSC Custom
# ---------------------------------------------------------------------------
_SSC_PROTOCOL = "ssc"
_SSC_PREFIX = "ssc://"
_SSC_START_RE = re.compile(r"(?i)(?<![A-Za-z0-9._-])ssc://")
_SSC_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_TRANSPORT_NOISE = frozenset({"`", "\u200b", "\u200c", "\u200d", "\ufeff"})


def _compact_text_fragment(text: str) -> str:
    """Quita únicamente ruido de transporte/Markdown que puede introducir Telegram."""
    return "".join(
        char
        for char in text
        if not char.isspace() and char not in _TRANSPORT_NOISE
    ).strip()


def _read_hex_payload(text: str) -> str | None:
    """Extrae una secuencia hexadecimal tolerando espacios y caracteres invisibles.

    A diferencia de la implementación anterior, no exige que todo el mensaje sea
    hexadecimal. Esto replica el comportamiento tolerante que ya funciona con
    Dark Tunnel y evita perder fragmentos pegados dentro de bloques de código o
    con caracteres invisibles de Telegram.
    """
    payload: list[str] = []
    started = False

    for char in text:
        if char in "0123456789abcdefABCDEF":
            payload.append(char)
            started = True
            continue
        if char.isspace() or char in _TRANSPORT_NOISE:
            continue
        if started:
            break

    value = "".join(payload)
    return value if value else None


def _extract_ssc_start(text: str) -> str | None:
    cleaned = text.replace("\ufeff", "").replace("\u200b", "").replace("\u200c", "").replace("\u200d", "")
    match = _SSC_START_RE.search(cleaned)
    if match is None:
        return None
    payload = _read_hex_payload(cleaned[match.end():])
    return _SSC_PREFIX + payload if payload else None


def _extract_ssc_continuation(text: str) -> str | None:
    compact = _compact_text_fragment(text)

    # Algunos clientes/copias pueden repetir el esquema en una parte posterior.
    if compact.lower().startswith(_SSC_PREFIX):
        compact = compact[len(_SSC_PREFIX):]

    if compact and _SSC_HEX_RE.fullmatch(compact):
        return compact

    # Fallback tolerante para bloques Markdown, saltos o caracteres invisibles.
    candidate = _read_hex_payload(text)
    if candidate and len(candidate) >= 8:
        meaningful = "".join(
            char for char in text
            if not char.isspace() and char not in _TRANSPORT_NOISE
        )
        noise_count = sum(
            1 for char in meaningful
            if char not in "0123456789abcdefABCDEF`"
        )
        # Durante una sesión activa permitimos un margen pequeño de decoración,
        # pero evitamos convertir mensajes normales en fragmentos SSC.
        if noise_count <= max(4, len(candidate) // 100):
            return candidate
    return None


def _is_ssc_text_message(message) -> bool:
    cleanup_expired(settings.text_session_timeout_seconds)
    text = _message_text(message)
    if _extract_ssc_start(text) is not None:
        return True
    session = get_session(message, settings.text_session_timeout_seconds)
    if session is None or session.protocol != _SSC_PROTOCOL:
        return False
    return _extract_ssc_continuation(text) is not None


def _send_incomplete_session(message, session, title: str, continuation_hint: str) -> None:
    timeout_minutes = max(1, settings.text_session_timeout_seconds // 60)
    bot.reply_to(
        message,
        f"<b>{html_pre(title)} detected</b>\n"
        f"Fragments received: <b>{session.parts}</b>. "
        f"Characters received: <b>{session.char_count:,}</b>.\n\n"
        "The text is still incomplete or invalid. "
        "The bot will try again after each fragment, "
        "regardless of how many messages are needed.\n"
        f"{continuation_hint}\n"
        f"The session expires after {timeout_minutes} minute(s) of inactivity. "
        "Use /cancel to discard it.",
        parse_mode="HTML",
    )


@bot.message_handler(func=_is_ssc_text_message)
@require_authorized("SSC Custom text")
def decode_ssc_text(message):
    """Decodifica SSC con el mismo patrón multipart dinámico usado por Dark Tunnel."""
    text = _message_text(message)
    start_payload = _extract_ssc_start(text)

    if start_payload is not None:
        # Igual que Dark Tunnel: la primera parte conserva el esquema y las
        # continuaciones se concatenan en orden de message_id.
        session = start_session(message, _SSC_PROTOCOL, start_payload)
    else:
        continuation = _extract_ssc_continuation(text)
        if continuation is None:
            return
        session = append_to_session(
            message,
            _SSC_PROTOCOL,
            continuation,
            settings.text_session_timeout_seconds,
        )

    if session is None:
        bot.reply_to(
            message,
            "There is no active SSC session. Send a message containing ssc:// first.",
        )
        return

    if session.char_count > settings.text_session_max_chars:
        clear_session(message, _SSC_PROTOCOL)
        bot.reply_to(
            message,
            "<b>SSC session canceled</b>\n"
            f"The assembled text exceeded the configured limit of "
            f"{settings.text_session_max_chars:,} characters.",
            parse_mode="HTML",
        )
        return

    try:
        # Mismo patrón de Dark Tunnel: el decodificador recibe directamente el
        # payload reconstruido completo después de cada parte recibida.
        result = decode_ssc_payload(session.payload.encode("utf-8"))
    except Exception:
        logger.exception("Internal error decoding SSC text")
        # Un error de decodificación durante multipart puede significar que aún
        # falta contenido. Conservamos la sesión, igual que en el flujo Dark.
        _send_incomplete_session(
            message,
            session,
            "SSC Custom",
            "Send the next hexadecimal fragment without repeating <code>ssc://</code>.",
        )
        return

    if result:
        clear_session(message, _SSC_PROTOCOL)
        send_markdown_result(message, "SSC Custom", result)
        return

    _send_incomplete_session(
        message,
        session,
        "SSC Custom",
        "Send the next hexadecimal fragment without repeating <code>ssc://</code>.",
    )


# ---------------------------------------------------------------------------
# Mensajes multipart: Dark Tunnel
# ---------------------------------------------------------------------------
_DARK_PROTOCOL = "dark"
_DARK_START_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9._-])"
    r"(?P<prefix>(?:[a-z0-9._-]*dark[a-z0-9._-]*|dtunnel|dt))://"
    r"(?P<payload>[A-Za-z0-9+/_=-]+)"
)
_DARK_CONTINUATION_RE = re.compile(r"^[A-Za-z0-9+/_=-]+$")


def _extract_dark_start(text: str) -> str | None:
    # Conserva los límites entre palabras para no unir texto normal con el esquema.
    cleaned = text.replace("`", "")
    match = _DARK_START_RE.search(cleaned)
    if match is None:
        return None
    # DARKTUNNEL.py acepta cualquier esquema y elimina todo lo anterior a ://.
    return f"{match.group('prefix')}://{match.group('payload')}"


def _extract_dark_continuation(text: str) -> str | None:
    compact = _compact_text_fragment(text)
    if not compact or _DARK_CONTINUATION_RE.fullmatch(compact) is None:
        return None
    return compact


def _is_dark_text_message(message) -> bool:
    cleanup_expired(settings.text_session_timeout_seconds)
    text = _message_text(message)
    if _extract_dark_start(text) is not None:
        return True
    session = get_session(message, settings.text_session_timeout_seconds)
    if session is None or session.protocol != _DARK_PROTOCOL:
        return False
    return _extract_dark_continuation(text) is not None


@bot.message_handler(func=_is_dark_text_message)
@require_authorized("Dark Tunnel text")
def decode_dark_text(message):
    """Decodifica enlaces Dark Tunnel aunque estén divididos en una cantidad variable de mensajes."""
    text = _message_text(message)
    start_payload = _extract_dark_start(text)

    if start_payload is not None:
        session = start_session(message, _DARK_PROTOCOL, start_payload)
    else:
        continuation = _extract_dark_continuation(text)
        if continuation is None:
            return
        session = append_to_session(
            message,
            _DARK_PROTOCOL,
            continuation,
            settings.text_session_timeout_seconds,
        )

    if session is None:
        bot.reply_to(
            message,
            "There is no active Dark Tunnel session. Send the link with the Dark Tunnel prefix first.",
        )
        return

    if session.char_count > settings.text_session_max_chars:
        clear_session(message, _DARK_PROTOCOL)
        bot.reply_to(
            message,
            "<b>Dark Tunnel session canceled</b>\n"
            f"The assembled text exceeded the configured limit of "
            f"{settings.text_session_max_chars:,} characters.",
            parse_mode="HTML",
        )
        return

    try:
        result = decode_dark_payload(session.payload.encode("utf-8"))
    except Exception:
        logger.exception("Internal error decoding Dark Tunnel text")
        clear_session(message, _DARK_PROTOCOL)
        bot.reply_to(
            message,
            "<b>Could not process Dark Tunnel</b>\n"
            "The decoder reported an internal error.",
            parse_mode="HTML",
        )
        return

    if result:
        clear_session(message, _DARK_PROTOCOL)
        send_markdown_result(message, "Dark Tunnel", result)
        return

    _send_incomplete_session(
        message,
        session,
        "Dark Tunnel",
        "Send the next fragment without repeating the <code>...://</code> prefix.",
    )


def cbc_iv(data):
    try:
        data = data.replace("\n", "")
        cipher = AES.new(b'poiuytrewqas+=~|', AES.MODE_CBC, b'r4tgv3b2zcmdW6ZZ')
        decrypted_data = cipher.decrypt(base64.b64decode(data))
        decrypted_data = decrypted_data.rstrip(b"\x00")  
        return decrypted_data.decode()
    except Exception as e:
        raise ValueError(f"Error in decryption: {e}")

def encode_base64(data):
    try:
        json_string = json.dumps(data)  
        encoded_data = base64.b64encode(json_string.encode()).decode()  
        return encoded_data
    except Exception as e:
        raise ValueError(f"Error in encoding: {e}")

@bot.message_handler(func=lambda message: 'howdy://' in _message_text(message) or 'N7pr://' in _message_text(message))
@require_authorized("Howdy configurations")
def handle_message(message):
    chat_id = message.chat.id
    text = message.text
    message_id = message.message_id

    try:
        decode = text.split('://')[1]
        data = base64.b64decode(decode)
        json_data = json.loads(data)
        username = json_data['username']
        password = json_data['password']
        port = json_data['port']
        server = cbc_iv(json_data['server'])
        sni = cbc_iv(json_data['sni'])
        config_type = json_data['type']
        linkserver = (
            "{\n"
            f" \"Username\": \"{username}\",\n"
            f" \"Password\": \"{password}\",\n"
            f" \"Server\": \"{server}\",\n"
            f" \"Sni\": \"{sni if sni else 'No SNI info'}\",\n"
            f" \"Port\": \"{port}\",\n"
            f" \"Type\": \"{config_type}\"\n"
            "}"
        )
        
        encoded_config = encode_base64(linkserver)
        send_markdown_result(
            message, "Howdy VPN", f"{linkserver}\n\nEncoded configuration:\nvmess://{encoded_config}",
        )
    except Exception as e:
        bot.send_message(
            chat_id, 
            "Could not decode the Howdy configuration. Resend it to try again.",
            reply_to_message_id=message_id
        )
        print(f"Error occurred: {str(e)}")
#######################################################
def remove_random_characters(text):
    return re.sub(r'[^a-zA-Z0-9/\:._-]', '', text)

def add_marker_to_lines(text, marker="│[۞] JSON:"):
    lines = text.splitlines()
    return "\n".join(f"{marker} {line}" for line in lines)

def obfuscate_text(text):
    return ''.join(chr(ord(c) + 1) for c in text)

@bot.message_handler(func=lambda message: any(token in _message_text(message) for token in ['nm-vmess://', 'nm-dns://', 'nm-vless://', 'nm-trojan://', 'nm-ssr://', 'nm-ssh://', 'nm-xray-json://']))
@require_authorized("NetMod configurations")
def decrypted_config(message):
    encrypted_text_base64 = message.text.strip()
    cle = 'X25ldHN5bmFfbmV0bW9kXw==' 
    pattern = r'^nm-(dns|ssr|vmess|vless|trojan|ssh|xray-json)://'
    cfg_type = re.match(pattern, encrypted_text_base64)

    try:
        if cfg_type:
            protocol = cfg_type.group(1)
            encryption_key = base64.b64decode(cle)
            config_encrypt = encrypted_text_base64[len(cfg_type[0]):]
            encrypted_text = base64.b64decode(config_encrypt)

            cipher = AES.new(encryption_key, AES.MODE_ECB)
            decrypt_text = unpad(cipher.decrypt(encrypted_text), AES.block_size)
            decrypt_text = decrypt_text.decode('utf-8')
            
            try:
                extracted_data = json.loads(decrypt_text)
                json_output = json.dumps(extracted_data, ensure_ascii=False, indent=4)
                encoded_config = base64.b64encode(decrypt_text.encode('utf-8')).decode('utf-8')
                output = f"{json_output}\n\nEncoded configuration:\n{protocol}://{encoded_config}"
            except json.JSONDecodeError:
                output = obfuscate_text(decrypt_text)
            send_markdown_result(message, f"NetMod · {protocol}", output)
        else:
            bot.reply_to(message, "Please enter a valid format.")
    except Exception as e:
        bot.reply_to(message, "Could not decode the NetMod configuration. Resend it to try again.")
        print(f"Error occurred: {str(e)}")
#######################################################
def decodificar_base64(data):
    try:
        decoded_data = base64.b64decode(data)
        return decoded_data.decode('utf-8')
    except Exception as e:
        return str(e)
        
@bot.message_handler(func=lambda message: "vmess://" in _message_text(message))
@require_authorized("VMess configurations")
def decodificar_vmess(message):
    start_index = message.text.find("vmess://")
    if start_index != -1:
        encoded_data = message.text[start_index + len("vmess://"):]
        decoded_data = decodificar_base64(encoded_data)
        configdict = json.loads(decoded_data)
        send_markdown_result(message, "VMess", json.dumps(configdict, indent=4))

######################################    
# Función para manejar mensajes con enlaces 'zivpn://'
#######################################################

class AESDecryptor:
    AES_MODE = AES.MODE_CBC
    AES_BLOCK_SIZE = 16
    HASH_ALGORITHM = 'SHA-256'
    INIT_VECTOR = b'\x00' * AES_BLOCK_SIZE

    @staticmethod
    def generate_key_from_password(password):
        return hashlib.sha256(password.encode()).digest()

    @staticmethod
    def pad_text(plain_text):
        padding_length = AESDecryptor.AES_BLOCK_SIZE - (len(plain_text) % AESDecryptor.AES_BLOCK_SIZE)
        return plain_text + bytes([padding_length] * padding_length)

    @staticmethod
    def unpad_text(padded_text):
        padding_length = padded_text[-1]
        return padded_text[:-padding_length]

    @staticmethod
    def decrypt_message(password, encrypted_text):
        key = AESDecryptor.generate_key_from_password(password)
        cipher = AES.new(key, AESDecryptor.AES_MODE, AESDecryptor.INIT_VECTOR)
        decoded_ciphertext = base64.b64decode(encrypted_text)
        decrypted_text = cipher.decrypt(decoded_ciphertext)
        unpadded_text = AESDecryptor.unpad_text(decrypted_text)
        return unpadded_text.decode()

@bot.message_handler(func=lambda message: 'zivpn://' in _message_text(message))
@require_authorized("ZI VPN configurations")
def handle_decryption(message):
    try:
        encoded_data = message.text.replace('zivpn://', '')
        base64_password = "dTlxdXdscWs4ODFkaTFneGpuMWF1YnkzZmFmdm9tOXQ="
        password = base64.b64decode(base64_password).decode('utf-8')
        decrypted_content = AESDecryptor.decrypt_message(password, encoded_data)
        content_lines = decrypted_content.split('\n')
        GhostDeveloper = ""
        for line in content_lines:
            if line.strip().startswith("<entry"):
                key_value_pair = line.strip().replace("<entry key=\"", "").replace("</entry>", "").replace('"/>', '').split("\">")
                if len(key_value_pair) > 1:
                    key, value = key_value_pair
                    GhostDeveloper += f"│[۞] {key}: {value}\n"
                else:
                    key = key_value_pair[0]
                    GhostDeveloper += f"│[۞] {key}: ***\n"

        send_markdown_result(message, "ZI VPN", GhostDeveloper)
    except Exception:
        bot.reply_to(message, "Could not decode the ZI VPN configuration.")
    
######################################


def zkjfh_wkef(qr, key, iv):
    cipher = AES.new(key.encode("utf-8"), AES.MODE_CBC, iv.encode("utf-8"))
    decrypted = cipher.decrypt(qr)
    return decrypted.rstrip(b"\0").decode("utf-8")

def es_json(cadena):
    try:
        json.loads(cadena)
        return True
    except ValueError:
        return False

def format_output(json_data):
    formatted = "\n".join([f"│[۞] {key}: {value}" for key, value in json_data.items()])
    return f"│[۞] Decoded Config:\n{formatted}"

@bot.message_handler(func=lambda message: any(proto in _message_text(message) for proto in ['pb-ssh://', 'pb-vless://', 'pb-vmess://', 'pb-trojan://', 'pb-socks://', 'pb-ss://']))
@require_authorized("XrayPB configurations")
def nmqwd_ksmns(message):
    protocols = ['pb-ssh://', 'pb-vless://', 'pb-vmess://', 'pb-trojan://', 'pb-socks://', 'pb-ss://']
    data = None
    for protocol in protocols:
        if protocol in message.text:
            data = message.text.split(protocol)[1]
            break

    if not data:
        return
    key = "4p+ocx+hGTnbDdHOmzQCjVb9KTTSh+A3"
    iv = "android123456789"

    try:
        decoded_data = b64decode(data)
        decrypted_data = zkjfh_wkef(decoded_data, key, iv)
        if es_json(decrypted_data):
            json_data = json.loads(decrypted_data)
            send_markdown_result(message, "XrayPB", format_output(json_data))
        else:
            bot.reply_to(message, "The decoded data is not valid JSON.")

    except Exception:
        bot.reply_to(message, "Could not decode the XrayPB configuration.")
########################################################        
def dec_ssh(ld):
    try:
        userlv = [i for i in ld.split('.')][::2]
        userld = [i for i in ld.split('.')][1::2]
        newld = ""

        for x in range(len(userld)):
            v = int(userlv[x]) - len(userlv)
            w = int(userld[x]) - len(userlv)
            m = int(v // (2 ** w)) % 256
            newld += chr(m)

        return newld
    except (ValueError, IndexError) as e:
        return None


@bot.message_handler(commands=['decssh'])
@require_authorized("SSH credentials")
def dec_ssh_command(message):
    encoded_data = message.text.replace("/decssh", "").strip()
    if '@' in encoded_data and ':' in encoded_data.split('@')[1]:
        try:
            ip_or_domain = encoded_data.split('@')[0]
            user_encoded = encoded_data.split('@')[1].split(':')[0]
            pass_encoded = encoded_data.split('@')[1].split(':')[1]
            user = dec_ssh(user_encoded)
            password = dec_ssh(pass_encoded)

            if user is not None and password is not None:
                send_markdown_result(
                    message, "SSH",
                    f"IP address or domain: {ip_or_domain}\nUsername: {user}\nPassword: {password}\n"
                    f"SSH: {ip_or_domain}@{user}:{password}",
                )
            else:
                bot.reply_to(message, "Error decoding user or password. Please check the input.")
        except Exception:
            bot.reply_to(message, "Could not decode the SSH credentials.")
    else:
        bot.reply_to(message, 'Data not detected in the command. Please provide valid data to decode.')
#######################################################
# Función que maneja el protocolo ar-
####################################################### 
Ghost_keys = {
    "Allowedit": "Allow edit",
    "Comp": "Comp",
    "Index": "Index",
    "Nowifi": "No WiFi",
    "Payload": "Payload",
    "Port": "Port",
    "Profile": "Profile",
    "Proxy": "Proxy",
    "Security": "Security",
    "SSH": "SSH"
}

@bot.message_handler(func=lambda message: _message_text(message).startswith('ar-'))
@require_authorized("AR Tunnel configurations")
def handle_armod(message):
    encrypted_text_base64 = message.text.strip()
    cle = 'YXJ0dW5uZWw3ODc5Nzg5eA==' 
    pattern = r'^ar-(dns|vless|vmess|trojan|ssr|socks|trojan-go|ssh)://'
    cfg_type = re.match(pattern, encrypted_text_base64)

    if cfg_type is None:
        return

    try:
        encryption_key = b64decode(cle)
        config_encrypt = encrypted_text_base64[len(cfg_type[0]):]
        encrypted_text = b64decode(config_encrypt)
        cipher = AES.new(encryption_key, AES.MODE_ECB)
        decrypt_text = unpad(cipher.decrypt(encrypted_text), AES.block_size)
        decrypt_text = decrypt_text.decode('utf-8')
        parsed_data = urllib.parse.parse_qs(decrypt_text)
        ssh_match = re.search(r'(\S+:\S+@\S+:\d+)', decrypt_text)
        ssh_data = ssh_match.group(1) if ssh_match else None
        payload = parsed_data.get('payload', [''])[0]
        if payload:
            payload = urllib.parse.unquote(payload)

        proxy = parsed_data.get('proxy', [''])[0]
        profile_raw = parsed_data.get('profile', [''])[0]
        index = parsed_data.get('index', [''])[0]
        allow_edit = parsed_data.get('allowedit', [''])[0]
        comp = parsed_data.get('comp', [''])[0]
        no_wifi = parsed_data.get('nowifi', [''])[0]
        security = parsed_data.get('security', [''])[0]
        profile = format_profile(profile_raw)
        result = f"""│[۞] Allow edit : {allow_edit}
│[۞] Comp : {comp}
│[۞] Index : {index}
│[۞] No WiFi : {no_wifi}
│[۞] Payload : {payload}
│[۞] Proxy : {proxy}
│[۞] Profile :\n{profile}
│[۞] Security : {security}
│[۞] SSH : {ssh_data if ssh_data else 'No SSH info'}
"""

        send_markdown_result(message, "AR Tunnel", result)

    except Exception as e:
        logger.exception("Internal error decoding the ar- format: %s", e)
        bot.reply_to(message, "Could not decode the AR Tunnel configuration.")

def format_profile(profile_raw):
    try:
        profile_data = json.loads(profile_raw)
        if isinstance(profile_data, list) and len(profile_data) > 0:
            profile_data = profile_data[0]
        if isinstance(profile_data, dict):
            return "\n".join(f"│[۞] {key}: {value}" for key, value in profile_data.items())
        return profile_raw
    except json.JSONDecodeError:
        return profile_raw
#######################################################
@bot.message_handler(func=lambda message: _message_text(message).startswith("v2box://"))
@require_authorized("V2Box configurations")
def decode_v2box(message):
    try:
        encoded_part = message.text.split("locked=")[1]

        decoded_part = base64.b64decode(encoded_part).decode('utf-8')

        parsed_url = urlparse(decoded_part)
        params = parse_qs(parsed_url.query)

        output = "\n".join(f"{key}: {', '.join(value)}" for key, value in params.items())
        send_markdown_result(message, "V2Box", output)

    except Exception:
        bot.reply_to(message, "Could not decode the V2Box configuration.")

        
#######################################################
# Función para procesar archivos
#######################################################


# ---------------------------------------------------------------------------
# RENZ / 7NET text protocols (shared Python engine with file extensions)
# ---------------------------------------------------------------------------
from decoders.Python.renz import (
    RENZ_TEXT_PROTOCOLS,
    MAX_INPUT_BYTES as RENZ_MAX_INPUT_BYTES,
    decode_text as decode_renz_payload,
)

_RENZ_PREFIXES = tuple(sorted(RENZ_TEXT_PROTOCOLS, key=len, reverse=True))


def _is_renz_text_message(message) -> bool:
    raw = _message_text(message).strip()
    return bool(raw) and len(raw) <= RENZ_MAX_INPUT_BYTES and raw.lower().startswith(_RENZ_PREFIXES)


@bot.message_handler(func=_is_renz_text_message)
@require_authorized("RENZ / 7NET text")
def decode_renz_text(message):
    payload = _message_text(message).strip()
    try:
        result = decode_renz_payload(payload)
    except Exception:
        logger.exception("Internal error decoding RENZ/7NET text")
        bot.reply_to(message, "Could not process RENZ / 7NET.")
        return
    if result is not None:
        send_markdown_result(message, "RENZ / 7NET", result)
    else:
        bot.reply_to(
            message,
            "Could not decode RENZ / 7NET. The protocol or configuration is unsupported.",
        )
