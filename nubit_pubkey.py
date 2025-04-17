import base64
import hashlib
import bech32
from ecdsa import SECP256k1, SigningKey
from bip_utils import (
    Bip39SeedGenerator, 
    Bip44,
    Bip44Coins,
    Bip39MnemonicValidator
)

def get_address(prefix, pubkey):
    sha = hashlib.sha256(pubkey).digest()
    rip = hashlib.new("ripemd160", sha).digest()
    return bech32.bech32_encode(prefix, bech32.convertbits(rip, 8, 5))

def main(mnemonic):
    passphrase = ""
    
    try:
        Bip39MnemonicValidator().Validate(mnemonic)
    except ValueError as e:
        print(f"Ошибка: {e}")
        return

    seed_bytes = Bip39SeedGenerator(mnemonic).Generate(passphrase)
    bip44_def_ctx = Bip44.FromSeed(seed_bytes, Bip44Coins.COSMOS).DeriveDefaultPath()
    
    priv_key_bytes = bip44_def_ctx.PrivateKey().Raw().ToBytes()
    priv_key_hex = priv_key_bytes.hex()
    
    priv_key = SigningKey.from_string(priv_key_bytes, curve=SECP256k1)
    pub_key_compressed = priv_key.get_verifying_key().to_string("compressed")
    pub_key_b64 = base64.b64encode(pub_key_compressed).decode("utf-8")
    
    address = get_address("nubit", pub_key_compressed)
    
    print(f"Приватный ключ (HEX): {priv_key_hex}")
    print(f"Публичный ключ: {pub_key_b64}")
    print(f"Адрес Nubit: {address}")

if __name__ == "__main__":
    try:
        mnemonic = input("Введите мнемонику: ").strip()
        main(mnemonic)
    except Exception as e:
        print(f"Критическая ошибка: {e}")
    input("\nНажмите Enter чтобы выйти...")  # Пауза перед закрытием
