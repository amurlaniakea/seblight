"""
RepoMapper: Repository Understanding for Coding Agents

Based on: "Probe-and-Refine Tuning of Repository Guidance for Coding Agents"
          (arXiv:2606.20512, Jun 2026)

Generates a compact AGENTS.md-style guide for any repository by:
1. Scanning the repository structure
2. Identifying subsystems, entry points, and conventions
3. Generating synthetic probes (bug-fix tasks)
4. Refining guidance based on probe results
5. Outputting a compact operational guide (< 3000 chars)
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class RepoMap:
    """Structured representation of a repository."""
    root: str
    name: str
    language: str
    total_files: int
    total_lines: int
    directories: list[str]
    entry_points: list[str]
    test_files: list[str]
    config_files: list[str]
    doc_files: list[str]
    subsystems: list[dict[str, Any]]
    dependencies: list[str]
    conventions: dict[str, Any]


@dataclass
class ProbeResult:
    """Result of a synthetic probe task."""
    probe_id: str
    description: str
    target_file: str
    expected_behavior: str
    actual_behavior: str | None
    passed: bool
    findings: list[str]


@dataclass
class Guidance:
    """Operational guidance for a repository."""
    content: str
    version: int
    probes_run: int
    probes_passed: int
    char_count: int
    sections: dict[str, str]


class RepoScanner:
    """Scans a repository and builds a structured map."""

    # File patterns
    ENTRY_POINT_PATTERNS = [
        "main.py", "app.py", "server.py", "cli.py", "__main__.py",
        "index.js", "index.ts", "server.ts", "app.ts",
        "main.go", "cmd/main.go",
        "src/main/java", "Main.java",
        "lib.rs", "main.rs",
    ]

    TEST_PATTERNS = [
        "test_", "_test.", "tests/", "/test/", "spec/", "_spec.",
        "conftest.py", "pytest.ini", "setup.cfg", "tox.ini",
        "jest.config", "vitest.config", "karma.conf",
    ]

    CONFIG_PATTERNS = [
        "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt",
        "package.json", "tsconfig.json", "Cargo.toml", "go.mod",
        "Makefile", "Dockerfile", "docker-compose", ".github/",
        "CMakeLists.txt", "pom.xml", "build.gradle",
    ]

    DOC_PATTERNS = [
        "README", "CONTRIBUTING", "CHANGELOG", "LICENSE",
        "docs/", "doc/", "wiki/", "ARCHITECTURE",
    ]

    IGNORE_DIRS = {
        ".git", ".svn", ".hg", "__pycache__", "node_modules",
        ".venv", "venv", "env", ".env", ".tox", ".mypy_cache",
        ".pytest_cache", "dist", "build", ".eggs", "*.egg-info",
        ".idea", ".vscode", ".vs",
    }

    def __init__(self, repo_path: str, max_depth: int = 3, max_files: int = 500):
        self.repo_path = Path(repo_path).resolve()
        self.max_depth = max_depth
        self.max_files = max_files
        if not self.repo_path.exists():
            raise FileNotFoundError(f"Repository not found: {repo_path}")

    def scan(self) -> RepoMap:
        """Scan the repository and return a structured map."""
        total_files = 0
        total_lines = 0
        directories = []
        entry_points = []
        test_files = []
        config_files = []
        doc_files = []
        language_stats: dict[str, int] = {}

        for root, dirs, files in os.walk(self.repo_path):
            # Filter ignored directories
            dirs[:] = [d for d in dirs if d not in self.IGNORE_DIRS and not d.startswith(".")]

            # Check depth
            rel_root = Path(root).relative_to(self.repo_path)
            depth = len(rel_root.parts) if str(rel_root) != "." else 0
            if depth > self.max_depth:
                dirs.clear()
                continue

            if str(rel_root) != ".":
                directories.append(str(rel_root))

            for file in files:
                if total_files >= self.max_files:
                    dirs.clear()
                    break

                file_path = Path(root) / file
                rel_path = str(file_path.relative_to(self.repo_path))

                total_files += 1

                # Count lines
                try:
                    with open(file_path, "r", errors="ignore") as f:
                        lines = len(f.readlines())
                        total_lines += lines
                except (PermissionError, OSError):
                    pass

                # Detect language
                ext = file_path.suffix
                lang_map = {
                    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
                    ".go": "Go", ".rs": "Rust", ".java": "Java",
                    ".rb": "Ruby", ".c": "C", ".cpp": "C++",
                    ".h": "C/C++", ".cs": "C#", ".php": "PHP",
                    ".swift": "Swift", ".kt": "Kotlin",
                }
                if ext in lang_map:
                    lang = lang_map[ext]
                    language_stats[lang] = language_stats.get(lang, 0) + 1

                # Classify file
                if self._matches_any(rel_path, self.ENTRY_POINT_PATTERNS):
                    entry_points.append(rel_path)
                if self._matches_any(rel_path, self.TEST_PATTERNS):
                    test_files.append(rel_path)
                if self._matches_any(rel_path, self.CONFIG_PATTERNS):
                    config_files.append(rel_path)
                if self._matches_any(rel_path, self.DOC_PATTERNS):
                    doc_files.append(rel_path)

        # Determine primary language
        language = max(language_stats, key=language_stats.get) if language_stats else "Unknown"

        # Identify subsystems
        subsystems = self._identify_subsystems(directories, test_files)

        # Extract dependencies
        dependencies = self._extract_dependencies()

        # Detect conventions
        conventions = self._detect_conventions()

        return RepoMap(
            root=str(self.repo_path),
            name=self.repo_path.name,
            language=language,
            total_files=total_files,
            total_lines=total_lines,
            directories=directories[:50],  # Limit for compactness
            entry_points=entry_points[:20],
            test_files=test_files[:30],
            config_files=config_files[:20],
            doc_files=doc_files[:10],
            subsystems=subsystems,
            dependencies=dependencies[:30],
            conventions=conventions,
        )

    def _matches_any(self, path: str, patterns: list[str]) -> bool:
        """Check if a path matches any of the patterns."""
        path_lower = path.lower()
        for pattern in patterns:
            if pattern.lower() in path_lower:
                return True
        return False

    def _identify_subsystems(self, directories: list[str], test_files: list[str]) -> list[dict[str, Any]]:
        """Identify subsystems based on directory structure and test coverage."""
        subsystems = []

        # Group directories by top-level
        top_level: dict[str, int] = {}
        for d in directories:
            parts = d.split("/")
            if len(parts) >= 2:
                top = parts[0]
                top_level[top] = top_level.get(top, 0) + 1

        # Identify subsystems (directories with > 1 subdir or test coverage)
        for name, count in sorted(top_level.items(), key=lambda x: -x[1]):
            if count > 0:
                # Find test files for this subsystem
                related_tests = [t for t in test_files if name.lower() in t.lower()]
                subsystems.append({
                    "name": name,
                    "file_count": count,
                    "has_tests": len(related_tests) > 0,
                    "test_files": related_tests[:5],
                })

        return subsystems[:15]

    def _extract_dependencies(self) -> list[str]:
        """Extract dependencies from config files."""
        deps = []

        # Python
        req_file = self.repo_path / "requirements.txt"
        if req_file.exists():
            with open(req_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        deps.append(line.split("==")[0].split(">=")[0].split("<=")[0])

        # Python (pyproject.toml)
        pyproject = self.repo_path / "pyproject.toml"
        if pyproject.exists():
            with open(pyproject) as f:
                content = f.read()
                # Simple extraction of dependencies section
                in_deps = False
                for line in content.split("\n"):
                    if "dependencies" in line and "=" in line:
                        in_deps = True
                        continue
                    if in_deps:
                        if line.strip().startswith("["):
                            break
                        match = re.match(r'\s*["\']([^"\']+)["\']', line)
                        if match:
                            deps.append(match.group(1))

        # Node.js
        package_json = self.repo_path / "package.json"
        if package_json.exists():
            try:
                with open(package_json) as f:
                    data = json.load(f)
                for section in ["dependencies", "devDependencies"]:
                    if section in data:
                        deps.extend(data[section].keys())
            except (json.JSONDecodeError, KeyError):
                pass

        return list(dict.fromkeys(deps))  # Deduplicate preserving order

    def _detect_conventions(self) -> dict[str, Any]:
        """Detect coding conventions from the repository."""
        conventions: dict[str, Any] = {}

        # Detect Python conventions
        py_files = list(self.repo_path.glob("*.py"))[:5]
        if py_files:
            has_type_hints = False
            has_docstrings = False
            uses_fstrings = False
            indent_style = "unknown"

            for py_file in py_files:
                try:
                    with open(py_file, "r", errors="ignore") as f:
                        content = f.read()

                    if "def " in content and "->" in content:
                        has_type_hints = True
                    if '"""' in content or "'''" in content:
                        has_docstrings = True
                    if 'f"' in content or "f'" in content:
                        uses_fstrings = True

                    # Detect indent
                    for line in content.split("\n"):
                        if line.startswith("    ") and not line.startswith("        "):
                            indent_style = "4 spaces"
                            break
                        elif line.startswith("\t"):
                            indent_style = "tabs"
                            break
                except (PermissionError, OSError):
                    continue

            conventions["python"] = {
                "type_hints": has_type_hints,
                "docstrings": has_docstrings,
                "f_strings": uses_fstrings,
                "indent": indent_style,
            }

        # Detect test framework
        test_files = list(self.repo_path.rglob("test_*.py"))[:3]
        if test_files:
            conventions["test_framework"] = "pytest"
        elif (self.repo_path / "package.json").exists():
            try:
                with open(self.repo_path / "package.json") as f:
                    pkg = json.load(f)
                dev_deps = pkg.get("devDependencies", {})
                if "jest" in dev_deps:
                    conventions["test_framework"] = "jest"
                elif "vitest" in dev_deps:
                    conventions["test_framework"] = "vitest"
                elif "mocha" in dev_deps:
                    conventions["test_framework"] = "mocha"
            except (json.JSONDecodeError, KeyError):
                pass

        # Detect build system
        if (self.repo_path / "Makefile").exists():
            conventions["build_system"] = "make"
        elif (self.repo_path / "pyproject.toml").exists():
            conventions["build_system"] = "setuptools/poetry"
        elif (self.repo_path / "package.json").exists():
            conventions["build_system"] = "npm/yarn"
        elif (self.repo_path / "Cargo.toml").exists():
            conventions["build_system"] = "cargo"
        elif (self.repo_path / "go.mod").exists():
            conventions["build_system"] = "go modules"

        return conventions


class ProbeGenerator:
    """Generates synthetic bug-fix probes for a repository."""

    def __init__(self, repo_map: RepoMap):
        self.repo_map = repo_map

    def generate_probes(self, count: int = 5) -> list[dict[str, Any]]:
        """Generate synthetic probe tasks."""
        probes = []

        # Probe 1: Can we run tests?
        probes.append({
            "id": "test_runner",
            "description": "Run the test suite",
            "type": "command",
            "command": self._detect_test_command(),
            "expected": "Tests run without import errors",
        })

        # Probe 2: Can we import the main module?
        if self.repo_map.language == "Python" and self.repo_map.entry_points:
            entry_mod = self.repo_map.entry_points[0].replace(".py", "").replace("/", ".")
            cmd = f"cd {self.repo_map.root} && python3 -c 'import {entry_mod}' 2>&1 || echo 'IMPORT_FAILED'"
            probes.append({
                "id": "import_check",
                "description": "Import the main module",
                "type": "command",
                "command": cmd,
                "expected": "Module imports successfully",
            })

        # Probe 3: Check config files are valid
        for config in self.repo_map.config_files[:2]:
            if config.endswith(".json"):
                probes.append({
                    "id": f"config_valid_{config.replace('/', '_')}",
                    "description": f"Validate {config}",
                    "type": "command",
                    "command": f"python3 -c 'import json; json.load(open(\"{self.repo_map.root}/{config}\"))' 2>&1",
                    "expected": "Valid JSON",
                })
            elif config.endswith(".toml"):
                probes.append({
                    "id": f"config_valid_{config.replace('/', '_')}",
                    "description": f"Validate {config}",
                    "type": "command",
                    "command": f"python3 -c 'import tomllib; tomllib.load(open(\"{self.repo_map.root}/{config}\", \"rb\"))' 2>&1",
                    "expected": "Valid TOML",
                })

        # Probe 4: Check for common issues
        probes.append({
            "id": "syntax_check",
            "description": "Check Python syntax",
            "type": "command",
            "command": f"cd {self.repo_map.root} && python3 -m py_compile $(find . -name '*.py' -not -path './.venv/*' -not -path './venv/*' | head -20) 2>&1 || echo 'SYNTAX_ERROR'",
            "expected": "No syntax errors",
        })

        # Probe 5: Subsystem structure
        if self.repo_map.subsystems:
            top_subsystem = self.repo_map.subsystems[0]
            probes.append({
                "id": "subsystem_structure",
                "description": f"Check {top_subsystem['name']} subsystem structure",
                "type": "command",
                "command": f"ls -la {self.repo_map.root}/{top_subsystem['name']}/ 2>&1 | head -10",
                "expected": "Subsystem directory exists and has files",
            })

        return probes[:count]

    def _detect_test_command(self) -> str:
        """Detect the test command for this repository."""
        root = self.repo_map.root

        if self.repo_map.language == "Python":
            if (Path(root) / "pytest.ini").exists() or (Path(root) / "conftest.py").exists():
                return f"cd {root} && python3 -m pytest --co -q 2>&1 | head -20"
            elif (Path(root) / "setup.py").exists() or (Path(root) / "pyproject.toml").exists():
                return f"cd {root} && python3 -m pytest --co -q 2>&1 | head -20"
            else:
                return f"cd {root} && python3 -m unittest discover -s . -p 'test_*.py' 2>&1 | head -20"

        elif self.repo_map.language in ("JavaScript", "TypeScript"):
            if (Path(root) / "package.json").exists():
                return f"cd {root} && npm test -- --listTests 2>&1 | head -20"
            else:
                return f"cd {root} && npx jest --listTests 2>&1 | head -20"

        elif self.repo_map.language == "Go":
            return f"cd {root} && go test -list . ./... 2>&1 | head -20"

        elif self.repo_map.language == "Rust":
            return f"cd {root} && cargo test -- --list 2>&1 | head -20"

        return f"cd {root} && echo 'No test command detected'"


class GuidanceGenerator:
    """Generates operational guidance from repo map and probe results."""

    def __init__(self, repo_map: RepoMap):
        self.repo_map = repo_map

    def generate(self, probes: list[dict[str, Any]] | None = None) -> Guidance:
        """Generate compact operational guidance."""
        sections: dict[str, str] = {}

        # Section 1: Overview
        sections["overview"] = self._gen_overview()

        # Section 2: Structure
        sections["structure"] = self._gen_structure()

        # Section 3: Entry Points
        if self.repo_map.entry_points:
            sections["entry_points"] = self._gen_entry_points()

        # Section 4: Testing
        sections["testing"] = self._gen_testing()

        # Section 5: Dependencies
        if self.repo_map.dependencies:
            sections["dependencies"] = self._gen_dependencies()

        # Section 6: Conventions
        if self.repo_map.conventions:
            sections["conventions"] = self._gen_conventions()

        # Section 7: Subsystems
        if self.repo_map.subsystems:
            sections["subsystems"] = self._gen_subsystems()

        # Section 8: Probe findings
        if probes:
            sections["findings"] = self._gen_findings(probes)

        # Combine sections
        content = self._combine_sections(sections)

        return Guidance(
            content=content,
            version=1,
            probes_run=len(probes) if probes else 0,
            probes_passed=sum(1 for p in probes if p.get("passed", False)) if probes else 0,
            char_count=len(content),
            sections=sections,
        )

    def _gen_overview(self) -> str:
        lines = [
            f"# {self.repo_map.name}",
            "",
            f"**Language:** {self.repo_map.language}  ",
            f"**Files:** {self.repo_map.total_files}  ",
            f"**Lines:** {self.repo_map.total_lines:,}  ",
            "",
        ]
        return "\n".join(lines)

    def _gen_structure(self) -> str:
        lines = ["## Structure", ""]
        # Show top-level directories
        top_dirs = set()
        for d in self.repo_map.directories:
            parts = d.split("/")
            if len(parts) == 1:
                top_dirs.add(parts[0])

        for d in sorted(top_dirs)[:15]:
            lines.append(f"- `{d}/`")

        lines.append("")
        return "\n".join(lines)

    def _gen_entry_points(self) -> str:
        lines = ["## Entry Points", ""]
        for ep in self.repo_map.entry_points[:10]:
            lines.append(f"- `{ep}`")
        lines.append("")
        return "\n".join(lines)

    def _gen_testing(self) -> str:
        lines = ["## Testing", ""]
        # Detect test command
        scanner = RepoScanner(self.repo_map.root)
        gen = ProbeGenerator(self.repo_map)
        test_cmd = gen._detect_test_command()
        # Extract just the command part
        if "&&" in test_cmd:
            cmd = test_cmd.split("&&")[-1].strip()
        else:
            cmd = test_cmd
        lines.append(f"**Test command:** `{cmd}`")
        lines.append("")

        if self.repo_map.test_files:
            lines.append("**Test files:**")
            for tf in self.repo_map.test_files[:10]:
                lines.append(f"- `{tf}`")
            lines.append("")

        return "\n".join(lines)

    def _gen_dependencies(self) -> str:
        lines = ["## Dependencies", ""]
        for dep in self.repo_map.dependencies[:20]:
            lines.append(f"- {dep}")
        if len(self.repo_map.dependencies) > 20:
            lines.append(f"- ... and {len(self.repo_map.dependencies) - 20} more")
        lines.append("")
        return "\n".join(lines)

    def _gen_conventions(self) -> str:
        lines = ["## Conventions", ""]
        for lang, conv in self.repo_map.conventions.items():
            if isinstance(conv, dict):
                items = ", ".join(f"{k}: {v}" for k, v in conv.items())
                lines.append(f"- **{lang}:** {items}")
            else:
                lines.append(f"- **{lang}:** {conv}")
        lines.append("")
        return "\n".join(lines)

    def _gen_subsystems(self) -> str:
        lines = ["## Subsystems", ""]
        for sub in self.repo_map.subsystems[:10]:
            test_info = " (has tests)" if sub["has_tests"] else " (no tests)"
            lines.append(f"- **{sub['name']}/** — {sub['file_count']} files{test_info}")
        lines.append("")
        return "\n".join(lines)

    def _gen_findings(self, probes: list[dict[str, Any]]) -> str:
        lines = ["## Probe Findings", ""]
        for probe in probes:
            status = "PASS" if probe.get("passed", False) else "FAIL"
            lines.append(f"- [{status}] {probe['description']}")
            if probe.get("findings"):
                for finding in probe["findings"]:
                    lines.append(f"  - {finding}")
        lines.append("")
        return "\n".join(lines)

    def _combine_sections(self, sections: dict[str, str]) -> str:
        """Combine sections into a compact guide (< 3000 chars)."""
        order = ["overview", "structure", "entry_points", "subsystems",
                 "testing", "dependencies", "conventions", "findings"]

        parts = []
        total_chars = 0

        for key in order:
            if key in sections:
                section = sections[key]
                if total_chars + len(section) > 2900:  # Leave margin
                    # Truncate last section
                    remaining = 2900 - total_chars
                    if remaining > 100:
                        parts.append(section[:remaining] + "\n\n...")
                    break
                parts.append(section)
                total_chars += len(section)

        return "\n".join(parts)


class RepoMapper:
    """
    Main class that orchestrates repository understanding.
    Scans, probes, and generates operational guidance.
    """

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.scanner = RepoScanner(repo_path)

    def map(self, run_probes: bool = True, probe_count: int = 5) -> dict[str, Any]:
        """
        Full pipeline: scan → probe → generate guidance.
        Returns a dict with repo_map, probes, and guidance.
        """
        start_time = time.time()

        # Step 1: Scan
        repo_map = self.scanner.scan()

        # Step 2: Generate and run probes
        probes: list[dict[str, Any]] = []
        if run_probes:
            probe_gen = ProbeGenerator(repo_map)
            probe_defs = probe_gen.generate_probes(probe_count)

            for probe_def in probe_defs:
                result = self._run_probe(probe_def)
                probes.append(result)

        # Step 3: Generate guidance
        guidance_gen = GuidanceGenerator(repo_map)
        guidance = guidance_gen.generate(probes)

        duration = time.time() - start_time

        return {
            "repo_map": {
                "name": repo_map.name,
                "language": repo_map.language,
                "total_files": repo_map.total_files,
                "total_lines": repo_map.total_lines,
                "entry_points": repo_map.entry_points,
                "test_files": repo_map.test_files,
                "config_files": repo_map.config_files,
                "subsystems": repo_map.subsystems,
                "dependencies": repo_map.dependencies,
                "conventions": repo_map.conventions,
            },
            "probes": probes,
            "guidance": {
                "content": guidance.content,
                "char_count": guidance.char_count,
                "probes_run": guidance.probes_run,
                "probes_passed": guidance.probes_passed,
                "sections": list(guidance.sections.keys()),
            },
            "duration_seconds": round(duration, 2),
        }

    def _run_probe(self, probe: dict[str, Any]) -> dict[str, Any]:
        """Run a single probe and return results."""
        result = {
            "id": probe["id"],
            "description": probe["description"],
            "type": probe["type"],
            "command": probe.get("command", ""),
            "expected": probe.get("expected", ""),
            "passed": False,
            "output": "",
            "findings": [],
        }

        if probe["type"] == "command":
            try:
                proc = subprocess.run(
                    probe["command"],
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=self.repo_path,
                )
                output = proc.stdout + proc.stderr
                result["output"] = output[:500]  # Limit output

                # Determine pass/fail
                if "IMPORT_FAILED" in output or "SYNTAX_ERROR" in output or "Traceback" in output:
                    result["passed"] = False
                    result["findings"].append(f"Error detected in output")
                elif proc.returncode != 0 and "No test command" not in output:
                    result["passed"] = False
                    result["findings"].append(f"Non-zero exit code: {proc.returncode}")
                else:
                    result["passed"] = True
                    result["findings"].append("Command executed successfully")

            except subprocess.TimeoutExpired:
                result["findings"].append("Probe timed out after 30s")
            except Exception as e:
                result["findings"].append(f"Probe error: {str(e)}")

        return result

    def export_guidance(self, output_path: str, run_probes: bool = True) -> str:
        """Generate and export guidance to a file."""
        result = self.map(run_probes=run_probes)
        guidance = result["guidance"]["content"]

        with open(output_path, "w") as f:
            f.write(guidance)

        return guidance


def main():
    """CLI entry point."""
    import argparse
    parser = argparse.ArgumentParser(description="RepoMapper: Repository Understanding for Coding Agents")
    parser.add_argument("repo_path", help="Path to the repository")
    parser.add_argument("--output", "-o", help="Output file for guidance (default: AGENTS.md)")
    parser.add_argument("--no-probes", action="store_true", help="Skip running probes")
    parser.add_argument("--probe-count", type=int, default=5, help="Number of probes to run")
    parser.add_argument("--json", action="store_true", help="Output full JSON result")
    args = parser.parse_args()

    mapper = RepoMapper(args.repo_path)
    result = mapper.map(run_probes=not args.no_probes, probe_count=args.probe_count)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        # Print summary
        rm = result["repo_map"]
        print(f"Repository: {rm['name']}")
        print(f"Language: {rm['language']}")
        print(f"Files: {rm['total_files']}")
        print(f"Lines: {rm['total_lines']:,}")
        print(f"Entry points: {len(rm['entry_points'])}")
        print(f"Test files: {len(rm['test_files'])}")
        print(f"Subsystems: {len(rm['subsystems'])}")
        print(f"Probes: {result['guidance']['probes_passed']}/{result['guidance']['probes_run']} passed")
        print(f"Guidance: {result['guidance']['char_count']} chars")
        print(f"Duration: {result['duration_seconds']}s")

    # Export guidance
    output = args.output or os.path.join(args.repo_path, "AGENTS.md")
    with open(output, "w") as f:
        f.write(result["guidance"]["content"])
    if not args.json:
        print(f"\nGuidance written to: {output}")


if __name__ == "__main__":
    main()
