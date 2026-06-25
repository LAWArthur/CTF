import urllib.parse

def gopher_http(endpoint: str, payload: str | bytes):
    encoded1 = urllib.parse.quote(payload)
    encodedrn = encoded1.replace('%0A', '%0D%0A')
    return f"gopher://{endpoint}/_{encodedrn}"

def gopher_bytes(endpoint: str, payload: bytes):
    encoded1 = urllib.parse.quote(payload)
    return f"gopher://{endpoint}/_{encoded1}"