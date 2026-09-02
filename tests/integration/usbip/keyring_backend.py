"""Minimal file-backed keyring used by the headless USB/IP integration job."""

import json
import os
from pathlib import Path

from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError


class Keyring(KeyringBackend):
    """Persist the wrapping key across separate ckman CLI processes."""

    priority = 1

    @property
    def _path(self) -> Path:
        return Path(os.environ["CKMAN_TEST_KEYRING_FILE"])

    def _read(self) -> dict[str, str]:
        try:
            with self._path.open(encoding="utf-8") as keyring_file:
                return json.load(keyring_file)
        except FileNotFoundError:
            return {}

    def _write(self, values: dict[str, str]) -> None:
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self._path.open("w", encoding="utf-8") as keyring_file:
            json.dump(values, keyring_file)
        self._path.chmod(0o600)

    @staticmethod
    def _entry(service: str, username: str) -> str:
        return f"{service}\0{username}"

    def get_password(self, service: str, username: str) -> str | None:
        return self._read().get(self._entry(service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        values = self._read()
        values[self._entry(service, username)] = password
        self._write(values)

    def delete_password(self, service: str, username: str) -> None:
        values = self._read()
        try:
            del values[self._entry(service, username)]
        except KeyError as error:
            raise PasswordDeleteError("Password not found") from error
        self._write(values)
