#!/usr/bin/python3
# ruff: noqa: UP045 -- deployed system Python is macOS 3.9
"""Fetch and securely stage the exact reviewed Hermes Agent source archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import ssl
import stat
import tarfile
import tempfile
import urllib.request
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Optional

COMMIT = "4281151ae859241351ba14d8c7682dc67ff4c126"
ARCHIVE_URL = "https://codeload.github.com/NousResearch/hermes-agent/tar.gz/" + COMMIT
ARCHIVE_SHA256 = "731f785d0373c81e7fb3d18ac5f4a1b6f9d6e3b94d2ae56a5b63133045bd2c68"
VERSION = "0.18.2"
ARCHIVE_ROOT = "hermes-agent-" + COMMIT
PROVENANCE_FILE = ".hermes-email-agent-provenance.json"
MAX_DOWNLOAD_BYTES = 96 * 1024 * 1024
MAX_EXTRACTED_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 100_000


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        _NoRedirect(),
    )


def download(destination: Path, *, timeout: float = 30.0) -> None:
    request = urllib.request.Request(
        ARCHIVE_URL,
        headers={"User-Agent": "hermes-email-bridge-source-fetch/0.3.0"},
        method="GET",
    )
    with _opener().open(request, timeout=timeout) as response:
        if response.geturl() != ARCHIVE_URL:
            raise ValueError("Hermes source download redirected")
        content_length = response.headers.get("Content-Length")
        if content_length and int(content_length) > MAX_DOWNLOAD_BYTES:
            raise ValueError("Hermes source archive exceeds the download size cap")
        _copy_capped(response, destination, MAX_DOWNLOAD_BYTES)


def _copy_capped(source: BinaryIO, destination: Path, limit: int) -> None:
    total = 0
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    raise ValueError("Hermes source archive exceeds the download size cap")
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)


def archive_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_archive(path: Path) -> None:
    if archive_sha256(path) != ARCHIVE_SHA256:
        raise ValueError("Hermes source archive SHA-256 mismatch")


def _safe_relative(member: tarfile.TarInfo) -> Path:
    name = PurePosixPath(member.name)
    if name.is_absolute() or not name.parts or name.parts[0] != ARCHIVE_ROOT:
        raise ValueError("Hermes archive has an unexpected root")
    relative = PurePosixPath(*name.parts[1:])
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("Hermes archive contains an unsafe path")
    return Path(*relative.parts)


def extract_verified(archive: Path, destination: Path) -> None:
    verify_archive(archive)
    if destination.is_symlink():
        raise ValueError("Hermes source destination cannot be a symlink")
    if destination.exists():
        verify_installed(destination)
        return
    _validate_stage_parent(destination.parent)
    stage_parent = Path(tempfile.mkdtemp(prefix=".hermes-agent-stage.", dir=destination.parent))
    stage = stage_parent / "source"
    try:
        stage.mkdir(mode=0o755)
    except Exception:
        shutil.rmtree(stage_parent, ignore_errors=True)
        raise
    seen: set[Path] = set()
    total = 0
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            members = bundle.getmembers()
            if len(members) > MAX_MEMBERS:
                raise ValueError("Hermes archive contains too many entries")
            for member in members:
                if member.name.rstrip("/") == ARCHIVE_ROOT:
                    if not member.isdir():
                        raise ValueError("Hermes archive root is not a directory")
                    continue
                relative = _safe_relative(member)
                if relative in seen:
                    raise ValueError("Hermes archive contains duplicate paths")
                seen.add(relative)
                target = stage / relative
                if os.path.commonpath((stage, target)) != str(stage):
                    raise ValueError("Hermes archive path escapes staging")
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=False, mode=0o755)
                    continue
                if not member.isreg():
                    raise ValueError("Hermes archive contains a link or special file")
                if member.size < 0:
                    raise ValueError("Hermes archive contains an invalid file size")
                total += member.size
                if total > MAX_EXTRACTED_BYTES:
                    raise ValueError("Hermes archive exceeds the extraction size cap")
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                source = bundle.extractfile(member)
                if source is None:
                    raise ValueError("Hermes archive regular file is unreadable")
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    with os.fdopen(descriptor, "wb", closefd=False) as output:
                        shutil.copyfileobj(source, output, length=1024 * 1024)
                        output.flush()
                        os.fsync(output.fileno())
                finally:
                    os.close(descriptor)
                os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
        _verify_version(stage)
        source_sha256 = _source_digest(stage)
        provenance = {
            "archive_sha256": ARCHIVE_SHA256,
            "archive_url": ARCHIVE_URL,
            "commit": COMMIT,
            "source_sha256": source_sha256,
            "version": VERSION,
        }
        provenance_path = stage / PROVENANCE_FILE
        provenance_path.write_text(json.dumps(provenance, sort_keys=True) + "\n")
        provenance_path.chmod(0o644)
        os.replace(stage, destination)
    finally:
        shutil.rmtree(stage_parent, ignore_errors=True)


def _verify_version(source: Path) -> None:
    pyproject_path = source / "pyproject.toml"
    if pyproject_path.is_symlink() or not pyproject_path.is_file():
        raise ValueError("Hermes source pyproject is not a regular file")
    pyproject = pyproject_path.read_text()
    if re.search(r'(?m)^version\s*=\s*"0\.18\.2"\s*$', pyproject) is None:
        raise ValueError("Hermes source does not report version 0.18.2")


def _source_digest(source: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source).as_posix()
        if relative == PROVENANCE_FILE:
            continue
        details = path.lstat()
        _validate_owner_mode(path, details)
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError("Hermes staged source contains a link or special file")
        digest.update(("D\0" if path.is_dir() else "F\0").encode())
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(f"{stat.S_IMODE(details.st_mode):04o}".encode())
        digest.update(b"\0")
        if stat.S_ISREG(details.st_mode):
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
    return digest.hexdigest()


def verify_installed(source: Path) -> None:
    if source.is_symlink() or not source.is_dir():
        raise ValueError("Hermes source target must be a regular directory")
    _validate_owner_mode(source, source.lstat())
    _verify_version(source)
    expected = {
        "archive_sha256": ARCHIVE_SHA256,
        "archive_url": ARCHIVE_URL,
        "commit": COMMIT,
        "version": VERSION,
    }
    provenance_path = source / PROVENANCE_FILE
    if provenance_path.is_symlink() or not provenance_path.is_file():
        raise ValueError("Hermes source provenance is missing or malformed")
    _validate_owner_mode(provenance_path, provenance_path.lstat())
    try:
        actual = json.loads(provenance_path.read_text())
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise ValueError("Hermes source provenance is missing or malformed") from exc
    if not isinstance(actual, dict) or actual.get("source_sha256") != _source_digest(source):
        raise ValueError("Hermes installed source digest does not match provenance")
    without_source_digest = dict(actual)
    without_source_digest.pop("source_sha256", None)
    if without_source_digest != expected:
        raise ValueError("Hermes source provenance does not match the reviewed source")


def fetch_and_stage(target: Path, *, timeout: float = 30.0) -> None:
    if target.is_symlink():
        raise ValueError("Hermes source destination cannot be a symlink")
    if target.exists():
        verify_installed(target)
        return
    _validate_stage_parent(target.parent)
    descriptor, archive_name = tempfile.mkstemp(
        prefix=".hermes-agent.", suffix=".tar.gz", dir=target.parent
    )
    os.close(descriptor)
    archive = Path(archive_name)
    archive.unlink()
    try:
        download(archive, timeout=timeout)
        extract_verified(archive, target)
    finally:
        archive.unlink(missing_ok=True)


def _validate_stage_parent(path: Path) -> None:
    details = path.lstat()
    if path.is_symlink() or not path.is_dir():
        raise ValueError("Hermes source staging parent must be a regular directory")
    _validate_owner_mode(path, details)


def _validate_owner_mode(path: Path, details: os.stat_result) -> None:
    if details.st_uid != os.geteuid():
        raise ValueError(f"Hermes source path is not owned by the installer account: {path}")
    if stat.S_IMODE(details.st_mode) & 0o022:
        raise ValueError(f"Hermes source path cannot be group/other writable: {path}")


def main(arguments: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args(arguments)
    if args.verify:
        verify_installed(args.target)
    else:
        fetch_and_stage(args.target)
    print(args.target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
