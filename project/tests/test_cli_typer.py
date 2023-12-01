from typer.testing import CliRunner

from project.main import app
from project.src.utils import create_signature

runner = CliRunner()


def test_app():
    result = runner.invoke(app, ["project/input_file.json", "project/private-key.pem"])
    assert result.exit_code == 0
    assert result.output == "File control_output.json created!\n"


def test_file_not_found():
    result = runner.invoke(app, ["project/input_file3.json", "project/private-key.pem"])
    assert result.exit_code == 2
    assert (
        "Error: Invalid value for 'ATTESTATION_FILE': "
        "'project/input_file3.json': No such file or directory"
    ) in result.output


def test_signature_creation(private_key):
    json_data = {
        "payload": {
            "type": "static-analysis",
            "result": {"vulnerabilities": 0, "warning": 2, "code_smells": 4},
            "user": "developer-1",
        }
    }

    json_data["signature"] = create_signature(private_key, json_data["payload"])

    assert json_data == {
        "payload": {
            "type": "static-analysis",
            "result": {"vulnerabilities": 0, "warning": 2, "code_smells": 4},
            "user": "developer-1",
        },
        "signature": "1d072473c94ecf0293dd3ec1470a566160b31b79c8ca54c72bfc77debd79af76f7da3dec9824dc731451670e4b5637"
        "3670c35fad753c4b38a8ef76424e89cf53b98160f3c6c9b9d39b8b49f0b855b847349dc28633edc446e889ebbc37d2"
        "b3e41dfd062a48fc5a2f50e2d8f42b49d5d21ce1edb8aab15858c82cd6d1759ee8aad25fbe0c2654e1802c89169c9b"
        "65c106eb402e06a3c30a293f56954e33c860db05ff5468607d5c959b9bdd15b24620cd201b3580097e43c37068769b"
        "a4a8c28d62b56819ff4cf76d2b47f42c140e4de3e9b16a979ae0f0e88bc5b3943764bcfd7fad89d6bd5adcaf02374f"
        "4dce356223f774f5035dd38db4525de7aa3b29d6b84864aa1ca1434a79bd3d71fbd6cca557639cb132dacaa1839e93"
        "3a986f3f0fa4fa0b470a1c1c37b2f732c35ad270f707cff01a92c6e8bfa3213aa74d200922cdc8513b6e8ce60d52bae"
        "07dce1f43bf0f629eb9620e032b9738f01b7a7a143c0b83c0619c377fefcd2d8be1d16c3c37b732efe829553438dfd"
        "9991b8451519c37",
    }
