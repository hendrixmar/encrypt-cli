from typing import Annotated, Dict, List
import typer
from src.utils import load_pem_string, load_json, write_json_file, create_signature

app = typer.Typer()


@app.command()
def signature(
        attestation_file: Annotated[
            typer.FileText,
            typer.Option(...)
        ],
        private_key_file: Annotated[
            typer.FileText,
            typer.Option(...)
        ],
        output_file: Annotated[
            str,
            typer.Option(...)
        ] = 'control_output.json'
) -> List[Dict[str, str]]:
    private_key = load_pem_string(private_key_file.read())
    attestations_data_signed = [
        {**data, "signature": create_signature(private_key, data)}
        for data in load_json(attestation_file.read())
    ]
    write_json_file(output_file, attestations_data_signed)
    typer.echo(f"File {output_file} created!")
    return attestations_data_signed


if __name__ == "__main__":
    app()
