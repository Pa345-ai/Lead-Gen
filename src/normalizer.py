"""
Input Normalizer
Accepts raw Solidity files → produces a runnable Foundry project.
Handles: compiler detection, dependency resolution, multi-file contracts.
"""

import os
import re
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class FoundryProject:
    foundry_root: str
    contracts: list
    compiler_version: str
    abi: dict = field(default_factory=dict)
    source_map: dict = field(default_factory=dict)
    raw_sources: dict = field(default_factory=dict)


class InputNormalizer:
    """
    Resolves a Solidity input into a runnable Foundry project.

    Handles:
    - Single .sol files
    - Directories of .sol files
    - Compiler version detection (pragma)
    - Basic OpenZeppelin dependency resolution
    - foundry.toml generation
    """

    COMPILER_PRAGMA_RE = re.compile(
        r'pragma\s+solidity\s+([^\s;]+)\s*;'
    )

    OZ_IMPORT_RE = re.compile(
        r'import\s+["\'](@openzeppelin/[^"\']+)["\']'
    )

    VERSION_RANGE_RE = re.compile(
        r'[\^~>=<]*(0\.\d+\.\d+)'
    )

    def __init__(self, contract_path: str, output_dir: str, verbose: bool = False):
        self.contract_path = Path(contract_path)
        self.output_dir = Path(output_dir)
        self.verbose = verbose
        self.foundry_root = self.output_dir / "foundry_project"

    def normalize(self) -> Optional[FoundryProject]:
        """Main entry: normalize input → Foundry project."""
        try:
            sources = self._collect_sources()
            if not sources:
                return None

            compiler_version = self._detect_compiler_version(sources)
            has_oz = self._detect_oz_imports(sources)

            self._scaffold_foundry(sources, has_oz, compiler_version)

            return FoundryProject(
                foundry_root=str(self.foundry_root),
                contracts=list(sources.keys()),
                compiler_version=compiler_version,
                raw_sources=sources
            )

        except Exception as e:
            if self.verbose:
                print(f"[normalizer] Error: {e}")
            return None

    def _collect_sources(self) -> dict:
        """Collect all Solidity source files."""
        sources = {}

        if self.contract_path.is_file():
            if self.contract_path.suffix == ".sol":
                sources[self.contract_path.name] = self.contract_path.read_text()
        elif self.contract_path.is_dir():
            for sol_file in sorted(self.contract_path.rglob("*.sol")):
                rel = sol_file.relative_to(self.contract_path)
                sources[str(rel)] = sol_file.read_text()
        else:
            raise FileNotFoundError(f"Not found: {self.contract_path}")

        if self.verbose:
            print(f"[normalizer] Collected {len(sources)} source file(s)")

        return sources

    def _detect_compiler_version(self, sources: dict) -> str:
        """Extract the most restrictive compiler version from pragma statements."""
        versions = []

        for name, src in sources.items():
            for match in self.COMPILER_PRAGMA_RE.finditer(src):
                version_str = match.group(1)
                ver = self._parse_version(version_str)
                if ver:
                    versions.append(ver)

        if not versions:
            return "0.8.19"  # safe default

        # Pick the highest compatible version
        versions.sort(key=lambda v: list(map(int, v.split("."))))
        resolved = versions[-1]

        # If < 0.8.0, flag for overflow vulnerability
        major, minor, patch = map(int, resolved.split("."))
        if minor < 8:
            if self.verbose:
                print(f"[normalizer] ⚠ Pre-0.8.0 compiler: overflow vulnerabilities possible")

        if self.verbose:
            print(f"[normalizer] Resolved compiler: solc {resolved}")

        return resolved

    def _parse_version(self, version_str: str) -> Optional[str]:
        """Parse a version constraint like ^0.8.0 or >=0.7.0 <0.9.0."""
        match = self.VERSION_RANGE_RE.search(version_str)
        if match:
            return match.group(1)
        return None

    def _detect_oz_imports(self, sources: dict) -> bool:
        """Check if OpenZeppelin imports are present."""
        for src in sources.values():
            if self.OZ_IMPORT_RE.search(src):
                if self.verbose:
                    print("[normalizer] OpenZeppelin imports detected")
                return True
        return False

    def _scaffold_foundry(self, sources: dict, has_oz: bool, compiler_version: str):
        """Create a Foundry project with the contracts placed correctly."""
        root = self.foundry_root
        root.mkdir(parents=True, exist_ok=True)

        # Write source contracts
        src_dir = root / "src"
        src_dir.mkdir(exist_ok=True)

        for name, content in sources.items():
            dest = src_dir / Path(name).name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content)

        # Write foundry.toml
        remappings = ""
        if has_oz:
            remappings = '\nremappings = ["@openzeppelin/=lib/openzeppelin-contracts/"]'

        foundry_toml = f"""[profile.default]
src = "src"
out = "out"
libs = ["lib"]
optimizer = true
optimizer_runs = 200
solc_version = "{compiler_version}"
fuzz = {{ runs = 256 }}
invariant = {{ runs = 64, depth = 15 }}{remappings}

[fmt]
line_length = 120
"""
        (root / "foundry.toml").write_text(foundry_toml)

        # Create test + script dirs
        (root / "test").mkdir(exist_ok=True)
        (root / "script").mkdir(exist_ok=True)
        (root / "lib").mkdir(exist_ok=True)

        # .gitignore
        (root / ".gitignore").write_text("out/\ncache/\n")

        # If OZ needed, create a stub or attempt forge install
        if has_oz:
            self._install_oz(root)

        if self.verbose:
            print(f"[normalizer] Foundry project scaffolded at {root}")

    def _install_oz(self, root: Path):
        """Attempt to install OpenZeppelin via forge."""
        try:
            result = subprocess.run(
                ["forge", "install", "openzeppelin/openzeppelin-contracts", "--no-commit"],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=60
            )
            if self.verbose:
                print(f"[normalizer] forge install OZ: {'ok' if result.returncode == 0 else 'failed'}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            if self.verbose:
                print("[normalizer] Warning: forge not found or timed out, OZ stubs may be needed")

    def get_contract_ast_text(self, contract_name: str) -> str:
        """Return raw source for a named contract."""
        for name, src in self._collect_sources().items():
            if Path(name).stem == contract_name or name == contract_name:
                return src
        return ""
