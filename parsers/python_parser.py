# parsers/python_parser.py
import jedi
from pathlib import Path
from typing import List, Dict, Any
from jedi.api.classes import Name
from .base_parser import BaseParser


class PythonParser(BaseParser):
    def __init__(self, repo_path: Path):
        super().__init__(repo_path)
        self.project = jedi.Project(self.repo_path)
        self.ignore = ["/test", "_test/", "/docs", "/example"]

    def extract_functions(
        self, symbol_name: str, code_line: str, filtered_files: List[Path]
    ) -> Dict:
        symbol_parts = symbol_name.split(".")
        matching_files = [
            f for f in filtered_files if self._search_string_in_file(f, code_line)
        ]
        scripts = (
            [jedi.Script(path=str(f), project=self.project) for f in matching_files]
            if matching_files
            else []
        )

        for func in [self.file_search, self.project_search, self.all_names_search]:
            match = func(symbol_name, symbol_parts, scripts, code_line)
            if match:
                return match

        print(f"No matches found for symbol: {symbol_name}")
        return {}

    def file_search(
        self, symbol_name: str, symbol_parts: List[str], scripts: List
    ) -> Dict[str, Any]:
        for script in scripts:
            for name in script.search(symbol_name):
                if self._should_exclude(str(name.module_path)):
                    continue
                match = self._resolve_match(name, symbol_name)
                if match:
                    return match
        return {}

    def project_search(self, symbol_name: str, *_args) -> Dict[str, Any]:
        for name in self.project.search(symbol_name):
            match = self._resolve_match(name, symbol_name)
            if match:
                return match
        return {}

    def all_names_search(
        self, symbol_name: str, symbol_parts: List[str], scripts: List, code_line: str
    ) -> Dict[str, Any]:
        for script in scripts:
            for name in script.get_names(
                all_scopes=True, definitions=True, references=True
            ):
                if name.full_name and name.full_name.endswith(symbol_name):
                    inferred = name.infer()
                    for inf in inferred:
                        return self._create_match_obj(inf, symbol_name)
                elif name.name == symbol_parts[-1]:
                    inferred = name.infer()
                    for inf in inferred:
                        return self._create_match_obj(inf, symbol_name)

        for script in scripts:
            cl = self._normalize(code_line)
            for name in script.get_names(all_scopes=True):
                if cl in self._normalize(name.description):
                    return self._create_match_obj(name, symbol_name)
                for inf in name.infer():
                    if cl in self._normalize(inf.description):
                        return self._create_match_obj(inf, symbol_name)
        return {}

    def _should_exclude(self, module_path: str) -> bool:
        return any(x in module_path.lower().replace("\\", "/") for x in self.ignore)

    def _search_string_in_file(self, file_path: Path, string: str) -> bool:
        try:
            with open(file_path, "r", encoding="utf-8") as file:
                return self._normalize(string) in self._normalize(file.read())
        except Exception:
            return False

    def _normalize(self, s: str) -> str:
        return (
            s.replace(" ", "")
            .replace("\n", "")
            .replace('"', "'")
            .replace("\r", "")
            .replace("\t", "")
        )

    def _resolve_match(self, name: Name, symbol_name: str) -> Dict[str, Any]:
        if name.type in ["function", "class", "statement", "instance", "module"]:
            if (
                symbol_name == name.name
                or symbol_name.endswith(f".{name.name}")
                or symbol_name in name.description
            ):
                inferred = name.infer()
                for inf in inferred:
                    return self._create_match_obj(inf, symbol_name)
                if name.type == "module":
                    loc = name.goto()
                    if loc:
                        return self._create_match_obj(loc[0], symbol_name)
        return {}

    def _create_match_obj(self, name: Name, symbol_name: str) -> Dict[str, Any]:
        module_path = str(name.module_path)
        if "/third_party/" in module_path or module_path == "None":
            source = f"Third party library. Claude, use what you already know about {name.full_name} to understand the code."
        else:
            start, end = (
                name.get_definition_start_position(),
                name.get_definition_end_position(),
            )
            source = self._get_definition_source(Path(name.module_path), start, end)
        return {
            "name": name.name,
            "context_name_requested": symbol_name,
            "file_path": str(name.module_path),
            "source": source,
        }

    def _get_definition_source(self, file_path: Path, start, end):
        try:
            with file_path.open(encoding="utf-8") as f:
                lines = f.readlines()
                if not start and not end:
                    return "".join(lines)
                definition = lines[start[0] - 1 : end[0]]
                end_len_diff = len(definition[-1]) - end[1]
                return (
                    "".join(definition)[start[1] : -end_len_diff]
                    if end_len_diff > 0
                    else "".join(definition)[start[1] :]
                ) or "None"
        except Exception:
            return "[Could not extract source]"
