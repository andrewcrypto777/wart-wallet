import base64
import os
import requests
import json
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from ecdsa import SigningKey, SECP256k1
from ecdsa.util import randrange_from_seed__trytryagain
from Crypto.Hash import RIPEMD160, SHA256
from pycoin.ecdsa.secp256k1 import secp256k1_generator
from hashlib import sha256
from random import randint


# encrypt private key
def encrypt_pk(pk, pw):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(pw.encode()))
    f = Fernet(key)
    pk_enc = f.encrypt(pk.encode())
    # return pk and salt
    return pk_enc.decode(), base64.b64encode(salt).decode('utf-8')


# decrypt private key
def decrypt_pk(pk_enc, pw, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=base64.b64decode(salt),
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(pw.encode()))
    f = Fernet(key)
    try:
        pkhex = f.decrypt(pk_enc.encode())
    except InvalidToken:
        # wrong password
        return None
    return pkhex.decode()


def wallet_from_seed(seed):
    # generate private key
    secexp = randrange_from_seed__trytryagain(seed, SECP256k1.order)
    pk = SigningKey.from_secret_exponent(secexp, curve=SECP256k1)

    return address_from_pk(pk), pk


def wallet_from_pkhex(pkhex):
    # generate private key
    pk = SigningKey.from_string(bytes.fromhex(pkhex),curve=SECP256k1)

    return address_from_pk(pk), pk


def address_from_pk(pk):
    pubkey = pk.get_verifying_key().to_string('compressed')

    # convert public key to raw addresss
    sha = SHA256.SHA256Hash(pubkey).digest()
    addr_raw = RIPEMD160.RIPEMD160Hash(sha).digest()
    addr_raw.hex()

    # generate address by appending checksum
    addr_hash = SHA256.SHA256Hash(addr_raw).digest()
    checksum = addr_hash[0:4]
    addr = addr_raw + checksum

    return addr.hex()


def send_tx(recipient, amount, fee, pk, peer):
    # get pinHash and pinHeight from warthog node
    head_raw = requests.get(peer + '/chain/head').content
    head = json.loads(head_raw)
    pinHash = head["data"]["pinHash"]
    pinHeight = head["data"]["pinHeight"]

    # send parameters
    nonceId = randint(0, 4294967295)  # 32 bit number, unique per pinHash and pinHeight
    toAddr = recipient
    amountE8 = amount  # 1 WART, this must be an integer, coin amount * 10E8

    # alternative: round fee from E8 amount
    rawFeeE8 = str(fee)  # this needs to be rounded
    result = requests.get(peer + '/tools/encode16bit/from_e8/' + rawFeeE8).content
    encode16bit_result = json.loads(result)
    feeE8 = encode16bit_result["data"]["roundedE8"]  # 9992

    # generate bytes to sign
    to_sign = \
        bytes.fromhex(pinHash) + \
        pinHeight.to_bytes(4, byteorder='big') + \
        nonceId.to_bytes(4, byteorder='big') + \
        b'\x00\x00\x00' + \
        feeE8.to_bytes(8, byteorder='big') + \
        bytes.fromhex(toAddr)[0:20] + \
        amountE8.to_bytes(8, byteorder='big')

    # create signature
    private_key = pk.privkey.secret_multiplier
    digest = sha256(to_sign).digest()

    # sign with recovery id
    (r, s, rec_id) = secp256k1_generator.sign_with_recid(private_key, int.from_bytes(digest, 'big'))

    # normalize to lower s
    if s > secp256k1_generator.order() / 2:  #
        s = secp256k1_generator.order() - s
        rec_id ^= 1  # https://github.com/bitcoin-core/secp256k1/blob/e72103932d5421f3ae501f4eba5452b1b454cb6e/src/ecdsa_impl.h#L295
    signature65 = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big') + rec_id.to_bytes(1,
                                                                                                      byteorder='big')

    # post transaction request to warthog node
    postdata = {
        "pinHeight": pinHeight,
        "nonceId": nonceId,
        "toAddr": toAddr,
        "amountE8": amountE8,
        "feeE8": feeE8,
        "signature65": signature65.hex()
    }
    rep = requests.post(peer + "/transaction/add", json=postdata)
    return rep.json()


# redirect to /auth/<token>
def set_token(window):
    r = window.evaluate_js('window.location.replace("http://localhost:50050/auth/" + window.pywebview.token.toString());')


# get balance for address
def get_balance(peer, addr):
    try:
        r = requests.get(f"{peer}/account/{addr}/balance")
        data = r.json()
        if data["code"] == 0:
            return data["data"]["balance"]
        else:
            return 0
    except requests.exceptions.RequestException:
        return None
