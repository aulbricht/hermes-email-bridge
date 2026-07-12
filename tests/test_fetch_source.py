from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
import tarfile
import urllib.request
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
FETCHER_PATH = ROOT / "deploy/macos/fetch-hermes-email-agent.py"


def _fetcher() -> Any:
    spec = importlib.util.spec_from_file_location("hermes_source_fetcher", FETCHER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _archive(path: Path, *, malicious: str | None = None) -> str:
    root = "hermes-agent-4281151ae859241351ba14d8c7682dc67ff4c126"
    with tarfile.open(path, "w:gz") as bundle:
        directory = tarfile.TarInfo(root)
        directory.type = tarfile.DIRTYPE
        bundle.addfile(directory)
        pyproject = b'[project]\nname = "hermes-agent"\nversion = "0.18.2"\n'
        project = tarfile.TarInfo(f"{root}/pyproject.toml")
        project.size = len(pyproject)
        bundle.addfile(project, io.BytesIO(pyproject))
        if malicious:
            item = tarfile.TarInfo(malicious)
            if malicious.endswith("symlink"):
                item.type = tarfile.SYMTYPE
                item.linkname = "/tmp/escape"
            elif malicious.endswith("hardlink"):
                item.type = tarfile.LNKTYPE
                item.linkname = f"{root}/pyproject.toml"
            elif malicious.endswith("device"):
                item.type = tarfile.CHRTYPE
            else:
                item.size = 1
            bundle.addfile(item, io.BytesIO(b"x") if item.isreg() else None)
        else:
            content = b"reviewed source\n"
            regular = tarfile.TarInfo(f"{root}/README.md")
            regular.size = len(content)
            bundle.addfile(regular, io.BytesIO(content))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_verified_archive_extracts_atomically_and_records_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fetcher = _fetcher()
    archive = tmp_path / "source.tar.gz"
    digest = _archive(archive)
    monkeypatch.setattr(fetcher, "ARCHIVE_SHA256", digest)
    target = tmp_path / "installed"
    fetcher.extract_verified(archive, target)

    assert (target / "README.md").read_text() == "reviewed source\n"
    provenance = json.loads((target / fetcher.PROVENANCE_FILE).read_text())
    assert provenance["archive_sha256"] == digest
    assert provenance["archive_url"] == fetcher.ARCHIVE_URL
    assert provenance["commit"] == fetcher.COMMIT
    assert provenance["version"] == "0.18.2"
    assert len(provenance["source_sha256"]) == 64
    fetcher.verify_installed(target)
    (target / "README.md").write_text("tampered\n")
    with pytest.raises(ValueError, match="digest"):
        fetcher.verify_installed(target)


@pytest.mark.parametrize(
    "malicious",
    [
        "/absolute",
        "hermes-agent-4281151ae859241351ba14d8c7682dc67ff4c126/../escape",
        "hermes-agent-4281151ae859241351ba14d8c7682dc67ff4c126/bad-symlink",
        "hermes-agent-4281151ae859241351ba14d8c7682dc67ff4c126/bad-hardlink",
        "hermes-agent-4281151ae859241351ba14d8c7682dc67ff4c126/bad-device",
    ],
)
def test_extraction_rejects_paths_links_and_special_files_without_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, malicious: str
) -> None:
    fetcher = _fetcher()
    archive = tmp_path / "malicious.tar.gz"
    monkeypatch.setattr(fetcher, "ARCHIVE_SHA256", _archive(archive, malicious=malicious))
    target = tmp_path / "installed"
    with pytest.raises(ValueError):
        fetcher.extract_verified(archive, target)
    assert not target.exists()


class _Response:
    def __init__(self, content: bytes, *, url: str, length: str | None = None) -> None:
        self._stream = io.BytesIO(content)
        self._url = url
        self.headers = {"Content-Length": length or str(len(content))}

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        pass

    def geturl(self) -> str:
        return self._url

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)


class _Opener:
    def __init__(self, response: _Response) -> None:
        self.response = response

    def open(self, *_args: object, **_kwargs: object) -> _Response:
        return self.response


def test_download_rejects_redirect_and_size_overflow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fetcher = _fetcher()
    redirected = _Response(b"content", url="https://attacker.example/archive")
    monkeypatch.setattr(fetcher, "_opener", lambda: _Opener(redirected))
    with pytest.raises(ValueError, match="redirected"):
        fetcher.download(tmp_path / "redirect.tar.gz")

    oversized = _Response(
        b"content",
        url=fetcher.ARCHIVE_URL,
        length=str(fetcher.MAX_DOWNLOAD_BYTES + 1),
    )
    monkeypatch.setattr(fetcher, "_opener", lambda: _Opener(oversized))
    with pytest.raises(ValueError, match="size cap"):
        fetcher.download(tmp_path / "large.tar.gz")


def test_fetch_rejects_symlink_destination(tmp_path: Path) -> None:
    fetcher = _fetcher()
    target = tmp_path / "source"
    target.symlink_to(tmp_path / "attacker", target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        fetcher.fetch_and_stage(target)


def test_extraction_rejects_writable_staging_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fetcher = _fetcher()
    archive = tmp_path / "source.tar.gz"
    monkeypatch.setattr(fetcher, "ARCHIVE_SHA256", _archive(archive))
    parent = tmp_path / "unsafe"
    parent.mkdir()
    parent.chmod(0o777)
    with pytest.raises(ValueError, match="group/other writable"):
        fetcher.extract_verified(archive, parent / "source")


def test_verification_rejects_writable_installed_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fetcher = _fetcher()
    archive = tmp_path / "source.tar.gz"
    monkeypatch.setattr(fetcher, "ARCHIVE_SHA256", _archive(archive))
    target = tmp_path / "installed"
    fetcher.extract_verified(archive, target)
    (target / "README.md").chmod(0o666)
    with pytest.raises(ValueError, match="group/other writable"):
        fetcher.verify_installed(target)


def test_fetcher_uses_fixed_proxy_free_https_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fetcher = _fetcher()
    assert fetcher.ARCHIVE_URL == (
        "https://codeload.github.com/NousResearch/hermes-agent/tar.gz/"
        "4281151ae859241351ba14d8c7682dc67ff4c126"
    )
    assert fetcher.ARCHIVE_SHA256 == (
        "731f785d0373c81e7fb3d18ac5f4a1b6f9d6e3b94d2ae56a5b63133045bd2c68"
    )
    captured: list[Any] = []

    def build_opener(*handlers: Any) -> object:
        captured.extend(handlers)
        return object()

    monkeypatch.setattr(fetcher.urllib.request, "build_opener", build_opener)
    fetcher._opener()
    proxy_handler = next(
        handler for handler in captured if isinstance(handler, urllib.request.ProxyHandler)
    )
    assert vars(proxy_handler).get("proxies") == {}
