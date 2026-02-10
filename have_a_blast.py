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

def encode_string(plaintext: str, secret: str, k: list) -> str:
    text = get_public(k)[:5000]
    key = _derive_key(text, secret)

    payload = plaintext.encode("utf-8")
    encrypted = _xor_encrypt(payload, key)

    return base64.urlsafe_b64encode(encrypted).decode("utf-8")

def _xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def decode_strings(token: str, secret: str, k: list) -> List[str]:
    text = get_public(k)[:5000]
    key = _derive_key(text, secret)
    encrypted = base64.urlsafe_b64decode(token)
    payload = _xor_encrypt(encrypted, key)
    return payload.decode('utf-8')

if __name__ == '__main__':
    SECRET = #
    another_mystry = #
    token="_9igyNUtTV_Uj5cU50yWAAB1m85461Ad7HIxusj-qNm636DFxmMHS8Scm0D2TYdFEHXUxWWkVxjmMTX5yO630rrAvdLVY0JTkJiHVu9AgUUFZNrfdfZBVOY_ILbP8ufb-9-1z4dpRkTXjYAU-UaNRQFuz99v6QQX-iEkttG3otvz3reHw2RCWdWE0kT2R4ENQ23OzGflQxGvPiW33_8="
    token2 = "9sugwMItUEvenNJB7U2NRQRt2s8g700X5HInts77o5f-z6TCy2JXCsaJglvxCYcLBGDcziDrUxqvOjGrz__nxfvIsM7TLURL3ouXWKNKkAAHaM-Lb-hNAupyPbzO9L6X98-mxsstRV_DkdJZ4l2BDUNvzt8g5ksV-3IzttP858P_xr6H02JXWtyN"
    
    v = input('Command:')
    
    try:
        if v == 'e':
            #f = 
            encoded = encode_string(f, SECRET, another_mystry)
            print(encoded)
        elif v == 'd':
            recovered = decode_strings(token, SECRET, another_mystry)
            print(recovered)
    except:
        print('Failed')

