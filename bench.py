import time, statistics, os, platform, importlib, sys

def med_us(fn, n):
    runs = []
    for _ in range(3):
        ts = []
        for _ in range(n):
            t = time.perf_counter_ns(); fn(); ts.append(time.perf_counter_ns() - t)
        runs.append(statistics.median(ts))
    return statistics.median(runs) / 1000

msg = os.urandom(32)
res = {}

import coincurve
k = coincurve.PrivateKey(); pub = k.public_key
sig = k.sign(msg); rsig = k.sign_recoverable(msg)
res["ECDSA verify (secp256k1)"] = med_us(lambda: pub.verify(sig, msg), 1500)
res["ECDSA recover"] = med_us(lambda: coincurve.PublicKey.from_signature_and_message(rsig, msg), 1500)

kem = importlib.import_module("pqcrypto.kem.ml_kem_1024")
pk, sk = kem.generate_keypair()
ct, ss = kem.encrypt(pk)
res["ML-KEM-1024 keygen"] = med_us(kem.generate_keypair, 1000)
res["ML-KEM-1024 encapsulate"] = med_us(lambda: kem.encrypt(pk), 1000)
res["ML-KEM-1024 decapsulate"] = med_us(lambda: kem.decrypt(sk, ct), 1000)

dsa = importlib.import_module("pqcrypto.sign.ml_dsa_87")
dpk, dsk = dsa.generate_keypair()
dsig = dsa.sign(dsk, msg)
res["ML-DSA-87 keygen"] = med_us(dsa.generate_keypair, 500)
res["ML-DSA-87 sign"] = med_us(lambda: dsa.sign(dsk, msg), 300)
res["ML-DSA-87 verify"] = med_us(lambda: dsa.verify(dpk, msg, dsig), 1000)

print(platform.processor() or platform.machine(), sys.version.split()[0])
for name, v in res.items():
    print(f"{name:28s} {v:10.1f} us")
v = res["ML-DSA-87 verify"]
print(f"\nML-DSA-87 verify / ECDSA recover: {v/res['ECDSA recover']:.1f}x")
print(f"ML-DSA-87 verify / ECDSA verify:  {v/res['ECDSA verify (secp256k1)']:.1f}x")
print(f"ML-DSA-87 verifies per core-second: {1e6/v:,.0f}")
print(f"1,000-tx block verify: {v*1000/1e6:.2f} s of one core")
