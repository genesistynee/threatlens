import os
import subprocess


MODEL = "gemma3:4b"


def ask_ollama(prompt):
    """
    Send a prompt to the local Gemma model through Ollama.

    Ollama is forced to use CPU because GPU initialization
    currently fails on this machine.
    """

    environment = os.environ.copy()
    environment["OLLAMA_LLM_LIBRARY"] = "cpu"

    result = subprocess.run(
        ["ollama", "run", MODEL, prompt],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=environment,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Ollama failed:\n{result.stderr}"
        )

    return result.stdout.strip()