import subprocess
import hashlib
import json
import base64
from typing import List

def get_public(k) -> str:
    result = subprocess.run(
        k,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return (result.stdout or '') + (result.stderr or '')

def _derive_key(text: str, secret: str) -> bytes:
    raw = (text + secret).encode('utf-8')
    return hashlib.sha256(raw).digest()

def _xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def decode_strings(token: str, secret: str, k: list) -> List[str]:
    text = get_public(k)
    key = _derive_key(text, secret)
    encrypted = base64.urlsafe_b64decode(token)
    payload = _xor_encrypt(encrypted, key)
    return json.loads(payload.decode('utf-8'))

if __name__ == '__main__':
    SECRET = #
    another_mystry = #
    token="NuWkBdJ06YRMDIvMQpbdDz-JA9jYR5V103lPyolQkcwCs6gUgje7hAFP3c9YnJhGPYdWiN5DjzKcLU-H3QadwBijpFWMO7nVFEPHwxXemkhuyUqZ2QDNMJJ5FJbMUNiUT62uAtJ1_t9CAImER4fYBnTGAdacAId10XkYlMxQ2JRPrqwHz2j-hEwMi8pWh90CP4kD2NhDj3fVf0_KiVCO2wLl7VeCefTSFEPEhBvSmAlo1leV0QDNMJJoAY_dF9aYTeWlHsVo_spCAImER4fUCXWHD9qeTpR312wKg4te1JYBsq8UyDnG"
    token2 = "NuWtFtJ8_oRMDIvRVpzOSDGFAY_SRo4ynC1PgcUTkJZB5-McyXjwhEwMi9FYgNYOP4kD2NhHl3XcYh3EhVLWwgy3rgWCN7uEBULOx1CXmEY9h0yN0gDNMJJlDJTaGtaYTeWzFsJ58tJCAImEVJPUCXjJAdacAIJi1WkEkote1JYCq6gBxTm3hkJBzNRUi5hGPYdOn8hDjTKcLU-E3AGNlkHn4xrBb_jOQgCJhFmHzkgxhQGY00OVMpwtT4XGHZ-WQefjA8V394RMDIvSWILKBniHfg=="
    try:
        recovered = decode_strings(token, SECRET, another_mystry)
        print(recovered)
    except:
        print('Failed')
