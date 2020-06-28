import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]
 
def encrypt(raw, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    raw = pad(raw)
    iv = bytes(password[0:16], "utf-8")#Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(bytes(raw, "utf-8"))
    return base64.b64encode(iv + encrypted)
 
 
def decrypt(enc, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))

plain = "This is secure message"
password = input("Enter encryption password: ")#demo219910R200609002
# First let us encrypt secret message
encrypted = encrypt(plain, password)
print("plain : " + plain)
print("encrypted : " + str(encrypted, "utf-8"))
 
# Let us decrypt using our original password
decrypted = decrypt(encrypted, password)
print("decrypted : " + bytes.decode(decrypted))