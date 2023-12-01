# Signatures generator
For this challenge, you need to process the data in control_output.json 
in such a way that you end up with the following structure:

```json
{
    "payload": {
        "type": "static-analysis",
        "result": {
            "vulnerabilities": 0,
            "warning": 2,
            "code_smells": 4
        },
        "user": "developer-1"
    },
    "signature": "1d072473c94ecf0293dd3ec1470a566160b31b79c8ca54c72bfc77debd79af76f7da3dec9824dc731451670e4b56373670c35fad753c4b38a8ef76424e89cf53b98160f3c6c9b9d39b8b49f0b855b847349dc28633edc446e889ebbc37d2b3e41dfd062a48fc5a2f50e2d8f42b49d5d21ce1edb8aab15858c82cd6d1759ee8aad25fbe0c2654e1802c89169c9b65c106eb402e06a3c30a293f56954e33c860db05ff5468607d5c959b9bdd15b24620cd201b3580097e43c37068769ba4a8c28d62b56819ff4cf76d2b47f42c140e4de3e9b16a979ae0f0e88bc5b3943764bcfd7fad89d6bd5adcaf02374f4dce356223f774f5035dd38db4525de7aa3b29d6b84864aa1ca1434a79bd3d71fbd6cca557639cb132dacaa1839e933a986f3f0fa4fa0b470a1c1c37b2f732c35ad270f707cff01a92c6e8bfa3213aa74d200922cdc8513b6e8ce60d52bae07dce1f43bf0f629eb9620e032b9738f01b7a7a143c0b83c0619c377fefcd2d8be1d16c3c37b732efe829553438dfd9991b8451519c37"
}
```



As you can see, the final structure is made of an object
from control_output.json plus a signature that was generated by signing the
json string representation of such object. Such structure is called an attestation.

That said, your objective is to generate a file called attestations.json which
is going contain a list of json objects representing the attestations for each
input object. For example:
```json
[
    {
        "payload": {
            "type": "static-analysis",
            "result": {
                "vulnerabilities": 0,
                "warning": 2,
                "code_smells": 4
            },
            "user": "developer-1"
        },
        "signature": "1d072473c94ecf0293dd3ec1470a566160b31b79c8ca54c72bfc77debd79af76f7da3dec9824dc731451670e4b56373670c35fad753c4b38a8ef76424e89cf53b98160f3c6c9b9d39b8b49f0b855b847349dc28633edc446e889ebbc37d2b3e41dfd062a48fc5a2f50e2d8f42b49d5d21ce1edb8aab15858c82cd6d1759ee8aad25fbe0c2654e1802c89169c9b65c106eb402e06a3c30a293f56954e33c860db05ff5468607d5c959b9bdd15b24620cd201b3580097e43c37068769ba4a8c28d62b56819ff4cf76d2b47f42c140e4de3e9b16a979ae0f0e88bc5b3943764bcfd7fad89d6bd5adcaf02374f4dce356223f774f5035dd38db4525de7aa3b29d6b84864aa1ca1434a79bd3d71fbd6cca557639cb132dacaa1839e933a986f3f0fa4fa0b470a1c1c37b2f732c35ad270f707cff01a92c6e8bfa3213aa74d200922cdc8513b6e8ce60d52bae07dce1f43bf0f629eb9620e032b9738f01b7a7a143c0b83c0619c377fefcd2d8be1d16c3c37b732efe829553438dfd9991b8451519c37"
    },
    {
        "payload": {
            "type": "static-analysis",
            "result": {
                "vulnerabilities": 1,
                "warning": 0, 
                "code_smells": 0
            },
            "user": "developer-3"
        },
        "signature": "558e8c3e72a9377433f8ce8eecf5972670263a28244420f73f6c1d54153b81c575264460f811e01c9b2ee671bc4b34184e452b973d99bb9f567bf360bb12bf50532da27d6a6935701247cc541cb66324dd4c6723d9684f588f86d8756e1c00caa6d10cdbce4509e4c20610cf50ef5bd589c021d88549166e9ab9520f7585778ad53bb881b9a90f8db19b906e0001b1137af4240a6abc7e67577c104c112d95a3a56f9723ace0264a628061cfa2db87fddfe9b53495e29c3d7fc48cc49fa0d6d9e42e77e4314d554f3cb3fa3c21d368e7aaf7d7c93adad5831a3a75ba1eeb0b213d5f7d1cf6845c60499155a6a539e2aceb6cd2d4b270d319ef189ff184307b6563c74a3f772729f8cb9a7c6d6705be36183b2b6abedc7fdc0a075d8be79766feb2945b54f19838827a3e754598540d0509520688ef8c83fb897b8bcdea95cd7366e293833b586b9ed8ee858a74e9a815affc1df467b2156be4ea2f57fb15c38e1e852488b592a90bb249449490771f04d03743abca4c82f327377e24f481bbd6"
    }
]
```
Now, you may be wondering how to generate the signature, for that you can use 
the following:
- https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#signing
- the private key to use is the file called private-key.pem
- the padding algo that you need to use is PKCS1v15 and the hashing algo is sha256.
- You can use your logic against the examples in this file to verify that you
  are generating the correct signatures.

# The solution

I decided to solve the challenge by taking an interesting library to create cli applications. Typer is a library for building CLI applications that users will love using and developers will love creating. Based on Python 3.6+ type hints.

To run the application you have run the main file with the following format:

```shell
pip install -r requirements.txt
```

```shell 
python main.py ${INPUT_FILE_PATH} ${PRIVATE_KEY_FILE_PATH}
```

For running the test 

```shell
pytest
```

I was thinking to give more options like accepting the link of the json file to create a signature
and then stored in a json output. 