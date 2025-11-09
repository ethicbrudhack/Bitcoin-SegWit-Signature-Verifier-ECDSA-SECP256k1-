import hashlib
import struct
from ecdsa import VerifyingKey, SECP256k1, util, ellipticcurve

def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def little_endian(hex_str):
    return bytes.fromhex(''.join(reversed([hex_str[i:i+2] for i in range(0, len(hex_str), 2)])))

def encode_varint(i):
    if i < 0xfd:
        return bytes([i])
    elif i <= 0xffff:
        return b'\xfd' + struct.pack('<H', i)
    elif i <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', i)
    else:
        return b'\xff' + struct.pack('<Q', i)

def hash_prevouts(inputs):
    data = b''.join(
        little_endian(inp["txid"]) + struct.pack("<I", inp["output"])
        for inp in inputs
    )
    return sha256d(data)

def hash_sequence(inputs):
    data = b''.join(
        struct.pack("<I", inp["sequence"])
        for inp in inputs
    )
    return sha256d(data)

def hash_outputs(outputs):
    data = b''
    for o in outputs:
        val = struct.pack("<Q", o["value"])
        script_pubkey = bytes.fromhex(o["pkscript"])
        data += val + encode_varint(len(script_pubkey)) + script_pubkey
    return sha256d(data)

def build_segwit_preimage(tx, input_index):
    inp = tx["inputs"][input_index]
    version = struct.pack("<I", tx["version"])
    hash_prev = hash_prevouts(tx["inputs"])
    hash_seq = hash_sequence(tx["inputs"])
    outpoint = little_endian(inp["txid"]) + struct.pack("<I", inp["output"])
    
    script_code = b'\x19' + bytes.fromhex("76a914" + inp["pkscript"][4:] + "88ac")
    amount = struct.pack("<Q", inp["value"])
    sequence = struct.pack("<I", inp["sequence"])
    hash_outs = hash_outputs(tx["outputs"])
    locktime = struct.pack("<I", tx["locktime"])
    sighash_type = struct.pack("<I", 1)
    
    preimage = (version + hash_prev + hash_seq + outpoint + script_code +
                amount + sequence + hash_outs + locktime + sighash_type)
    return sha256d(preimage)

def decompress_pubkey(compressed_hex):
    compressed = bytes.fromhex(compressed_hex)
    prefix = compressed[0]
    x = int.from_bytes(compressed[1:], "big")
    curve = SECP256k1.curve
    p = curve.p()
    y_sq = (x**3 + 7) % p
    y = pow(y_sq, (p+1)//4, p)
    if (prefix == 0x02 and y % 2 != 0) or (prefix == 0x03 and y % 2 == 0):
        y = p - y
    return ellipticcurve.Point(curve, x, y)

# ----- PODSTAWIONA TRANSAKCJA -----
tx = {
    "txid": "20c1bb76b0b82527fd4d948ab8ae14895f60ff80fb71ed05dd022da64247dfac",
    "version": 1,
    "locktime": 0,
    "inputs": [
        {
            "coinbase": False,
            "txid": "26b80c6bc2c59d0e1b90b620d50e50200cdaeffb69436aea1318b71d443c8083",
            "output": 1,
            "sigscript": "",
            "sequence": 4294967295,
            "pkscript": "0014dc6bf86354105de2fcd9868a2b0376d6731cb92f",
            "value": 23382232,
            "address": "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h",
            "witness": [
                "304402206216579c3aa0801a7cc327e96a980549b5a3df1903fa21ab100f5bdc2d138bbe02207f0eda2c46dffebfd8fb630878eba1a7b46b0a8f2afc6762ff3e253abfa267bc01",
                "02174ee672429ff94304321cdae1fc1e487edf658b34bd1d36da03761658a2bb09"
            ]
        }
    ],
    "outputs": [
        {
            "address": "bc1qe7fgq066c7yrsfk8lppxfwss7ffcydjkntpq7knfv3fm36lxdgzqkv4mtl",
            "pkscript": "0020cf92803f5ac7883826c7f84264ba10f2538236569ac20f5a696453b8ebe66a04",
            "value": 9000
        },
        {
            "address": "bc1qm34lsc65zpw79lxes69zkqmk6ee3ewf0j77s3h",
            "pkscript": "0014dc6bf86354105de2fcd9868a2b0376d6731cb92f",
            "value": 6156546
        },
        {
            "address": "bc1qv9f0n5jwkjd8u8ctkqncvkh7stgvpt8zxvsttl",
            "pkscript": "00146152f9d24eb49a7e1f0bb027865afe82d0c0ace2",
            "value": 13775
        },
        {
            "address": "1M9t2AcGmgSBHRzpfLWkiWzybhrFRCgujV",
            "pkscript": "76a914dd106ecc252562370bd702ce6fb1188e9976300088ac",
            "value": 12097000
        },
        {
            "address": "bc1qam9m4mkgve4mxte4wkkpzkrja3e8telhpx4l22",
            "pkscript": "0014eecbbaeec8666bb32f3575ac115872ec7275e7f7",
            "value": 242160
        },
        {
            "address": "127FRJ8fuJyQwwN8zj3Ufgu2SHjLg3QMqL",
            "pkscript": "76a9140c26a867d4d5716c451d1321322443a9669fbbee88ac",
            "value": 85291
        },
        {
            "address": "1JZkeMzeWG2ioZp2sFcrQ3pHCYMva8aGMj",
            "pkscript": "76a914c0abe1a4d4b25dc6719e5e6561ab878704a5d4f488ac",
            "value": 117400
        },
        {
            "address": "1K1FYBBXo9NWJYLsqFmF8hoQjbCq6zneFD",
            "pkscript": "76a914c57e663fb6d5b665fcfdec55be5f3c574add66d688ac",
            "value": 381862
        },
        {
            "address": "1Fw24Ufz4oG4Jk5FdumVDwnMCpXE4dSPFz",
            "pkscript": "76a914a3c91b92f79dc0e684ab799b4fa97e721bb947de88ac",
            "value": 67886
        },
        {
            "address": "1GKsTUdwpJksGzNtTYHPT9HHBUguQEgb6S",
            "pkscript": "76a914a81b7e3700b22534ec83e3ebab90b6dfabbcd6e488ac",
            "value": 1276783
        },
        {
            "address": "bc1qd8esur4mm328r275ykdg96udq550n0z4qdq5q5",
            "pkscript": "001469f30e0ebbdc5471abd4259a82eb8d0528f9bc55",
            "value": 179432
        },
        {
            "address": "bc1p5s3dcgqywng0tma2k5w8dc2wlrkltg8m2eah3hnvgjmh7gkedugsszkq9q",
            "pkscript": "5120a422dc200474d0f5efaab51c76e14ef8edf5a0fb567b78de6c44b77f22d96f11",
            "value": 2263252
        },
        {
            "address": "bc1qfd339p3athd39usqhmle2c5s5x88px43yvjs3x",
            "pkscript": "00144b6312863d5ddb12f200beff956290a18e709ab1",
            "value": 238400
        },
        {
            "address": "39wsUAm6oPPqKSvUbDaoiARq1sGv5XXRtw",
            "pkscript": "a9145a9030235899a3a8d04194f7f07df13581bb610787",
            "value": 247885
        }
    ]
}

# Weryfikacja podpisu
i = 0
inp = tx["inputs"][i]
z_hash = build_segwit_preimage(tx, i)

der_sig = bytes.fromhex(inp["witness"][0])
der_sig_no_type = der_sig[:-1]
r, s = util.sigdecode_der(der_sig_no_type, SECP256k1.order)
signature = util.sigencode_string(r, s, SECP256k1.order)

pubkey_hex = inp["witness"][1]
point = decompress_pubkey(pubkey_hex)
vk = VerifyingKey.from_public_point(point, curve=SECP256k1)

print(f"z      = {z_hash.hex()}")
print(f"r      = {r:064x}")
print(f"s      = {s:064x}")
print(f"pubkey = {pubkey_hex}")

try:
    verified = vk.verify_digest(signature, z_hash)
    print("✅ Podpis jest poprawny!")
except Exception as e:
    print("❌ Błąd weryfikacji podpisu:", e)
