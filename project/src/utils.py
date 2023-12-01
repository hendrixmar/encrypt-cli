import json
from typing import Dict, List

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.dh import DHPrivateKey
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey

EncryptionTypes = (
    DHPrivateKey
    | Ed25519PrivateKey
    | Ed448PrivateKey
    | RSAPrivateKey
    | DSAPrivateKey
    | EllipticCurvePrivateKey
    | X25519PrivateKey
    | X448PrivateKey
)


def load_pem_string(data: str) -> EncryptionTypes:
    """
    Create the private key signature with a keu
    """
    return serialization.load_pem_private_key(
        data.encode(), password=None, backend=default_backend()
    )


def write_json_file(file_name: str, data: List[Dict[str, str]]) -> None:
    """
    Writes the sequence of dictionary to an json file
    """
    with open(file_name, "w") as json_file:
        json.dump(data, json_file, indent=4)


def load_json(json_data: str) -> List[Dict[str, str]]:
    """
    Load a json to list of dictionary
    """
    return json.loads(json_data)


def create_signature(private_key: EncryptionTypes, data: Dict[str, str]) -> str:
    json_bytes = json.dumps(data).encode("utf-8")
    signature = private_key.sign(json_bytes, padding.PKCS1v15(), hashes.SHA256())
    return signature.hex()
