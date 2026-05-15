"""
Security Tool (Modern approach using Typer)
===========================================
Typer leverages Python's type hints for clean, readable CLI code.
"""

import typer

# Initialize the Typer app
app = typer.Typer(help="A modern network security scanner.")


@app.command()
def scan(
        target: str = typer.Argument(..., help="The target IP address or hostname."),
        port: int = typer.Option(80, "--port", "-p", help="Target port number."),
        verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose output.")
):
    """
    Perform a scan on the specified target.
    """
    typer.echo(f"[*] Starting scan for: {target}")
    typer.echo(f"[*] Port set to: {port}")

    if verbose:
        typer.echo("[+] Verbose mode: Enabling full packet analysis.")

    typer.echo("[+] Scan finished.")


if __name__ == "__main__":
    app()