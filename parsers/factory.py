# parsers/factory.py
from pathlib import Path
from parsers.python_parser import PythonParser


def get_parser(language: str, repo_path: Path):
    if language == "python":
        return PythonParser(repo_path)
    raise ValueError(f"Unsupported language: {language}")
