# parsers/base_parser.py
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict


class BaseParser(ABC):
    def __init__(self, repo_path: Path):
        self.repo_path = repo_path

    @abstractmethod
    def extract_functions(
        self, symbol_name: str, code_line: str, files: List[Path]
    ) -> Dict:
        pass
