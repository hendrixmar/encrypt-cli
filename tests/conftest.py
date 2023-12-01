import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from src.utils import EncryptionTypes


@pytest.fixture
def private_key() -> EncryptionTypes:
    with open('private-key.pem', 'rb') as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )