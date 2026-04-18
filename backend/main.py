import typer
from backend.pipeline import process_report

app = typer.Typer()

@app.command()
def convert(
    input_path: str = typer.Argument(..., help="Path to the intelligence report"),
    output_name: str = typer.Option("stix_bundle_final.json", help="Output filename"),
):
    output_path = process_report(input_path, output_name)
    typer.echo(f"Final bundle saved to {output_path}")

if __name__ == "__main__":
    app()