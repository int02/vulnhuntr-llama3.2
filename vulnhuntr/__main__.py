# __main__.py
import json
import re
import argparse
import structlog
from vulnhuntr.LLMs import Claude, ChatGPT, Ollama
from vulnhuntr.prompts import *
from rich import print
from typing import List, Generator
from enum import Enum
from pathlib import Path
from pydantic_xml import BaseXmlModel, element
from pydantic import BaseModel, Field
from parsers.factory import get_parser
import dotenv
import os
import html

dotenv.load_dotenv()

structlog.configure(
    processors=[structlog.processors.JSONRenderer()],
    logger_factory=structlog.WriteLoggerFactory(
        file=Path("vulnhuntr").with_suffix(".log").open("wt")
    ),
)

import faulthandler

faulthandler.enable()

log = structlog.get_logger("vulnhuntr")


class VulnType(str, Enum):
    LFI = "LFI"
    RCE = "RCE"
    SSRF = "SSRF"
    AFO = "AFO"
    SQLI = "SQLI"
    XSS = "XSS"
    IDOR = "IDOR"


class ContextCode(BaseModel):
    name: str = Field(description="Function or Class name")
    reason: str = Field(
        description="Brief reason why this function's code is needed for analysis"
    )
    code_line: str = Field(
        description="The single line of code where where this context object is referenced."
    )


class Response(BaseModel):
    scratchpad: str = Field(
        description="Your step-by-step analysis process. Output in plaintext with no line breaks."
    )
    analysis: str = Field(
        description="Your final analysis. Output in plaintext with no line breaks."
    )
    poc: str = Field(description="Proof-of-concept exploit, if applicable.")
    confidence_score: int = Field(
        description="0-10, where 0 is no confidence and 10 is absolute certainty because you have the entire user input to server output code path."
    )
    vulnerability_types: List[VulnType] = Field(
        description="The types of identified vulnerabilities"
    )
    context_code: List[ContextCode] = Field(
        description="List of context code items requested for analysis, one function or class name per item. No standard library or third-party package code."
    )


class ReadmeContent(BaseXmlModel, tag="readme_content"):
    content: str


class ReadmeSummary(BaseXmlModel, tag="readme_summary"):
    readme_summary: str


class Instructions(BaseXmlModel, tag="instructions"):
    instructions: str


class ResponseFormat(BaseXmlModel, tag="response_format"):
    response_format: str


class AnalysisApproach(BaseXmlModel, tag="analysis_approach"):
    analysis_approach: str


class Guidelines(BaseXmlModel, tag="guidelines"):
    guidelines: str


class FileCode(BaseXmlModel, tag="file_code"):
    file_path: str = element()
    file_source: str = element()


class PreviousAnalysis(BaseXmlModel, tag="previous_analysis"):
    previous_analysis: str


class ExampleBypasses(BaseXmlModel, tag="example_bypasses"):
    example_bypasses: str


class CodeDefinition(BaseXmlModel, tag="code"):
    name: str = element()
    context_name_requested: str = element()
    file_path: str = element()
    source: str = element()


class CodeDefinitions(BaseXmlModel, tag="context_code"):
    definitions: List[CodeDefinition] = []


class RepoOps:
    def __init__(self, repo_path: Path | str) -> None:
        self.repo_path = Path(repo_path)
        self.to_exclude = {
            "/setup.py",
            "/test",
            "/example",
            "/docs",
            "/site-packages",
            ".venv",
            "virtualenv",
            "/dist",
        }
        self.file_names_to_exclude = ["test_", "conftest", "_test.py"]

        patterns = [
            # Async
            r"async\sdef\s\w+\(.*?request",
            # Gradio
            r"gr.Interface\(.*?\)",
            r"gr.Interface\.launch\(.*?\)",
            # Flask
            r"@app\.route\(.*?\)",
            r"@blueprint\.route\(.*?\)",
            r"class\s+\w+\(MethodView\):",
            r"@(?:app|blueprint)\.add_url_rule\(.*?\)",
            # FastAPI
            r"@app\.(?:get|post|put|delete|patch|options|head|trace)\(.*?\)",
            r"@router\.(?:get|post|put|delete|patch|options|head|trace)\(.*?\)",
            # Django
            r"url\(.*?\)",  # Too broad?
            r"re_path\(.*?\)",
            r"@channel_layer\.group_add",
            r"@database_sync_to_async",
            # Pyramid
            r"@view_config\(.*?\)",
            # Bottle
            r"@(?:route|get|post|put|delete|patch)\(.*?\)",
            # Tornado
            r"class\s+\w+\((?:RequestHandler|WebSocketHandler)\):",
            r"@tornado\.gen\.coroutine",
            r"@tornado\.web\.asynchronous",
            # WebSockets
            r"websockets\.serve\(.*?\)",
            r"@websocket\.(?:route|get|post|put|delete|patch|head|options)\(.*?\)",
            # aiohttp
            r"app\.router\.add_(?:get|post|put|delete|patch|head|options)\(.*?\)",
            r"@routes\.(?:get|post|put|delete|patch|head|options)\(.*?\)",
            # Sanic
            r"@app\.(?:route|get|post|put|delete|patch|head|options)\(.*?\)",
            r"@blueprint\.(?:route|get|post|put|delete|patch|head|options)\(.*?\)",
            # Falcon
            r"app\.add_route\(.*?\)",
            # CherryPy
            r"@cherrypy\.expose",
            # web2py
            r"def\s+\w+\(\):\s*return\s+dict\(",
            # Quart (ASGI version of Flask)
            r"@app\.route\(.*?\)",
            r"@blueprint\.route\(.*?\)",
            # Starlette (which FastAPI is based on)
            r"@app\.route\(.*?\)",
            r"Route\(.*?\)",
            # Responder
            r"@api\.route\(.*?\)",
            # Hug
            r"@hug\.(?:get|post|put|delete|patch|options|head)\(.*?\)",
            # Dash (for analytical web applications)
            r"@app\.callback\(.*?\)",
            # GraphQL entry points
            r"class\s+\w+\(graphene\.ObjectType\):",
            r"@strawberry\.type",
            # Generic decorators that might indicate custom routing
            r"@route\(.*?\)",
            r"@endpoint\(.*?\)",
            r"@api\.\w+\(.*?\)",
            # AWS Lambda handlers (which could be used with API Gateway)
            r"def\s+lambda_handler\(event,\s*context\):",
            r"def\s+handler\(event,\s*context\):",
            # Azure Functions
            r"def\s+\w+\(req:\s*func\.HttpRequest\)\s*->",
            # Google Cloud Functions
            r"def\s+\w+\(request\):"
            # Server startup code
            r"app\.run\(.*?\)",
            r"serve\(app,.*?\)",
            r"uvicorn\.run\(.*?\)",
            r"application\.listen\(.*?\)",
            r"run_server\(.*?\)",
            r"server\.start\(.*?\)",
            r"app\.listen\(.*?\)",
            r"httpd\.serve_forever\(.*?\)",
            r"tornado\.ioloop\.IOLoop\.current\(\)\.start\(\)",
            r"asyncio\.run\(.*?\.serve\(.*?\)\)",
            r"web\.run_app\(.*?\)",
            r"WSGIServer\(.*?\)\.serve_forever\(\)",
            r"make_server\(.*?\)\.serve_forever\(\)",
            r"cherrypy\.quickstart\(.*?\)",
            r"execute_from_command_line\(.*?\)",  # Django's manage.py
            r"gunicorn\.app\.wsgiapp\.run\(\)",
            r"waitress\.serve\(.*?\)",
            r"hypercorn\.run\(.*?\)",
            r"daphne\.run\(.*?\)",
            r"werkzeug\.serving\.run_simple\(.*?\)",
            r"gevent\.pywsgi\.WSGIServer\(.*?\)\.serve_forever\(\)",
            r"grpc\.server\(.*?\)\.start\(\)",
            r"app\.start_server\(.*?\)",  # Sanic
            r"Server\(.*?\)\.run\(\)",  # Bottle
        ]

        # Compile the patterns for efficiency
        self.compiled_patterns = [re.compile(pattern) for pattern in patterns]

    def get_readme_content(self) -> str:
        # Use glob to find README.md or README.rst in a case-insensitive manner in the root directory
        prioritized_patterns = [
            "[Rr][Ee][Aa][Dd][Mm][Ee].[Mm][Dd]",
            "[Rr][Ee][Aa][Dd][Mm][Ee].[Rr][Ss][Tt]",
        ]

        # First, look for README.md or README.rst in the root directory with case insensitivity
        for pattern in prioritized_patterns:
            for readme in self.repo_path.glob(pattern):
                with readme.open(encoding="utf-8") as f:
                    return f.read()

        # If no README.md or README.rst is found, look for any README file with supported extensions
        for readme in self.repo_path.glob("[Rr][Ee][Aa][Dd][Mm][Ee]*.[Mm][DdRrSsTt]"):
            with readme.open(encoding="utf-8") as f:
                return f.read()

        return

    def get_relevant_py_files(self) -> Generator[Path, None, None]:
        """Gets all Python files in a repo minus the ones in the exclude list (test, example, doc, docs)"""
        files = []
        for f in self.repo_path.rglob("*.py"):
            # Convert the path to a string with forward slashes
            f_str = str(f).replace("\\", "/")

            # Lowercase the string for case-insensitive matching
            f_str = f_str.lower()

            # Check if any exclusion pattern matches a substring of the full path
            if any(exclude in f_str for exclude in self.to_exclude):
                continue

            # Check if the file name should be excluded
            if any(fn in f.name for fn in self.file_names_to_exclude):
                continue

            files.append(f)

        return files

    def get_network_related_files(self, files: List) -> Generator[Path, None, None]:
        for py_f in files:
            with py_f.open(encoding="utf-8") as f:
                content = f.read()
            if any(re.search(pattern, content) for pattern in self.compiled_patterns):
                yield py_f

    def detect_language(file_path: Path) -> str:
        ext = file_path.suffix.lower()
        return {
            ".py": "python",
            ".js": "javascript",
            ".ts": "typescript",
            ".go": "go",
            ".c": "c",
            ".cpp": "cpp",
            ".rs": "rust",
        }.get(ext, "unknown")

    def get_files_to_analyze(self, analyze_path: Path | None = None) -> List[Path]:
        path_to_analyze = analyze_path or self.repo_path
        if path_to_analyze.is_file():
            return [path_to_analyze]
        elif path_to_analyze.is_dir():
            return path_to_analyze.rglob("*.py")
        else:
            raise FileNotFoundError(
                f"Specified analyze path does not exist: {path_to_analyze}"
            )


def extract_between_tags(tag: str, string: str, strip: bool = False) -> list[str]:
    ext_list = re.findall(f"<{tag}>(.+?)</{tag}>", string, re.DOTALL)
    if strip:
        ext_list = [e.strip() for e in ext_list]
    return ext_list


def initialize_llm(llm_arg: str, system_prompt: str = "") -> Claude | ChatGPT | Ollama:
    llm_arg = llm_arg.lower()
    if llm_arg == "claude":
        anth_model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
        anth_base_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com")
        llm = Claude(anth_model, anth_base_url, system_prompt)
    elif llm_arg == "gpt":
        openai_model = os.getenv("OPENAI_MODEL", "chatgpt-4o-latest")
        openai_base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
        llm = ChatGPT(openai_model, openai_base_url, system_prompt)
    elif llm_arg == "ollama":
        ollama_model = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
        ollama_base_url = os.getenv(
            "OLLAMA_BASE_URL", "http://127.0.0.1:11434/api/generate"
        )
        llm = Ollama(ollama_model, ollama_base_url, system_prompt)
    else:
        raise ValueError(
            f"Invalid LLM argument: {llm_arg}\nValid options are: claude, gpt, ollama"
        )
    return llm


def print_readable(report: Response) -> None:
    for attr, value in vars(report).items():
        print(f"{attr}:")
        if isinstance(value, str):
            for line in value.split("\n"):
                print(f"  {line}")
        elif isinstance(value, list):
            for item in value:
                print(f"  - {item}")
        else:
            print(f"  {value}")
        print("-" * 40)
        print()


def run():
    parser = argparse.ArgumentParser(
        description="Analyze a GitHub project for vulnerabilities. Export your ANTHROPIC_API_KEY/OPENAI_API_KEY before running."
    )
    parser.add_argument("-r", "--root", type=str, required=True)
    parser.add_argument("-a", "--analyze", type=str)
    parser.add_argument(
        "-l", "--llm", type=str, choices=["claude", "gpt", "ollama"], default="claude"
    )
    parser.add_argument("-v", "--verbosity", action="count", default=0)
    args = parser.parse_args()

    repo = RepoOps(args.root)
    files = repo.get_relevant_py_files()

    if args.analyze:
        analyze_path = Path(args.analyze)
        if analyze_path.is_absolute():
            files_to_analyze = repo.get_files_to_analyze(analyze_path)
        else:
            files_to_analyze = repo.get_files_to_analyze(Path(args.root) / analyze_path)
    else:
        files_to_analyze = repo.get_network_related_files(files)

    llm = initialize_llm(args.llm)

    readme_content = repo.get_readme_content()
    if readme_content:
        log.info("Summarizing project README")
        summary_raw = llm.chat(
            (
                ReadmeContent(content=readme_content).to_xml()
                + b"\n"
                + Instructions(instructions=README_SUMMARY_PROMPT_TEMPLATE).to_xml()
            ).decode()
        )
        summaries = extract_between_tags("summary", summary_raw, strip=True)
        summary = summaries[0] if summaries else ""
        log.info("README summary complete", summary=summary)
    else:
        log.warning("No README summary found")
        summary = ""

    system_prompt = (
        Instructions(instructions=SYS_PROMPT_TEMPLATE).to_xml()
        + b"\n"
        + ReadmeSummary(readme_summary=summary).to_xml()
    ).decode()

    llm = initialize_llm(args.llm, system_prompt)

    for py_f in files_to_analyze:
        log.info(f"Performing initial analysis", file=str(py_f))
        with py_f.open(encoding="utf-8") as f:
            content = f.read()
            if not len(content):
                continue

            print(f"\nAnalyzing {py_f}")
            print("-" * 40 + "\n")

            user_prompt = (
                FileCode(file_path=str(py_f), file_source=content).to_xml()
                + b"\n"
                + Instructions(instructions=INITIAL_ANALYSIS_PROMPT_TEMPLATE).to_xml()
                + b"\n"
                + AnalysisApproach(
                    analysis_approach=ANALYSIS_APPROACH_TEMPLATE
                ).to_xml()
                + b"\n"
                + PreviousAnalysis(previous_analysis="").to_xml()
                + b"\n"
                + Guidelines(guidelines=GUIDELINES_TEMPLATE).to_xml()
            ).decode()

            max_retries = 10
            for attempt in range(1, max_retries + 1):
                raw_response = llm.chat(user_prompt)
                raw_response = html.unescape(raw_response)
                json_blocks = extract_between_tags("json", raw_response, strip=True)
                if not json_blocks:
                    # Attempt to extract JSON from code block
                    match = re.search(r"``````", raw_response, re.DOTALL)
                    if match:
                        json_response = match.group(1)
                    else:
                        if attempt == max_retries:
                            print(
                                "❌ No <json>...</json> block or code block found after "
                                f"{max_retries} attempts. Full response:\n",
                                raw_response,
                            )
                            raise ValueError("No JSON block found in LLM response")
                        else:
                            log.warning(
                                f"Attempt {attempt} failed to find JSON block, retrying..."
                            )
                            continue
                else:
                    json_response = json_blocks[0]
                # Add missing braces if necessary
                json_response = json_response.strip()
                if not json_response.startswith("{"):
                    json_response = "{" + json_response
                if not json_response.endswith("}"):
                    json_response = json_response + "}"

                try:
                    initial_analysis_report: Response = Response.model_validate_json(
                        json_response
                    )
                    break  # success, exit retry loop
                except Exception as e:
                    if attempt == max_retries:
                        print(
                            f"❌ JSON validation failed after {max_retries} attempts: {e}"
                        )
                        print("Raw JSON response:\n", json_response)
                        raise
                    else:
                        log.warning(
                            f"Attempt {attempt} JSON validation failed: {e}, retrying..."
                        )
                        continue

            log.info(
                "Initial analysis complete", report=initial_analysis_report.model_dump()
            )
            print_readable(initial_analysis_report)


if __name__ == "__main__":
    run()
