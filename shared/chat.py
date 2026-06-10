import struct

MSG_TEST = 0x00
MSG_CHAT = 0x01

MAX_CHAT_LEN = 4096


def pack_chat_message(text: str) -> bytes:
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_CHAT_LEN:
        raise ValueError(f"Chat message too long ({len(encoded)} bytes, max {MAX_CHAT_LEN})")
    return struct.pack("!B", MSG_CHAT) + struct.pack("!H", len(encoded)) + encoded


def unpack_message(data: bytes) -> tuple:
    if len(data) < 1:
        raise ValueError("Packet too short for message type")
    msg_type = data[0]
    payload = data[1:]
    return msg_type, payload


def unpack_chat_payload(data: bytes) -> str:
    if len(data) < 2:
        raise ValueError("Chat payload too short for length header")
    text_len = struct.unpack("!H", data[:2])[0]
    if len(data) < 2 + text_len:
        raise ValueError("Chat payload truncated")
    return data[2:2 + text_len].decode("utf-8")
