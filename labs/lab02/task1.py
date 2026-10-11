from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

PBKDF2_ITERATIONS = 210_000
SESSION_TIMEOUT_SEC = 900
EMAIL_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]{2,63}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


class User:
    def __init__(
        self, username: str, email: str, role: str = "user", active: bool = True
    ) -> None:
        self.username = username
        self._email = ""
        self.email = email
        self.role = role
        self.active = active
        self.__password_hash = b""
        self.__password_salt = b""

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str) or not EMAIL_PATTERN.fullmatch(value):
            raise ValueError("Invalid email format")
        self._email = value

    def set_password(self, password: str) -> None:
        if not isinstance(password, str) or len(password) < 8:
            raise ValueError("Password must contain at least 8 characters")
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, PBKDF2_ITERATIONS
        )

    def check_password(self, password: str) -> bool:
        if not isinstance(password, str) or not self.__password_hash:
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, PBKDF2_ITERATIONS
        )
        return hmac.compare_digest(candidate, self.__password_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        return f"User(username={self.username}, role={self.role}, active={self.active})"


class Admin(User):
    def __init__(
        self,
        username: str,
        email: str,
        permissions: set[str] | None = None,
        active: bool = True,
    ) -> None:
        super().__init__(username, email, role="admin", active=active)
        self.permissions = set() if permissions is None else set(permissions)

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        permissions = ", ".join(sorted(self.permissions)) or "none"
        return f"Admin(username={self.username}, permissions={permissions})"


@dataclass
class Session:
    ip: str
    login_time: datetime
    last_activity: datetime

    def touch(self) -> None:
        self.last_activity = datetime.now(UTC)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("timeout_sec must be positive")
        now = datetime.now(UTC)
        return now - self.last_activity <= timedelta(seconds=timeout_sec)


@dataclass(frozen=True)
class AuditRecord:
    timestamp: datetime
    username: str
    action: str


class AuditLog:
    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def add_log(self, username: str, action: str) -> None:
        self.records.append(AuditRecord(datetime.now(UTC), username, action))

    def show_all(self) -> list[AuditRecord]:
        return list(self.records)


class UserAccount:
    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.user = user
        self.session = session
        self.audit_log = AuditLog() if audit_log is None else audit_log

    def login(self, username: str, password: str, ip: str) -> bool:
        if (
            username != self.user.username
            or not self.user.active
            or not self.user.check_password(password)
        ):
            self.audit_log.add_log(username, "login_failure")
            return False
        now = datetime.now(UTC)
        self.session = Session(ip, now, now)
        self.session.touch()
        self.audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        return self.session is not None and self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        if self.session is not None:
            self.session = None
            self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key: str) -> Any:
        allowed = {"user", "session", "audit_log"}
        if key not in allowed:
            raise KeyError(key)
        return getattr(self, key)

    def __setitem__(self, key: str, value: Any) -> None:
        expected = {
            "user": User,
            "session": (Session, type(None)),
            "audit_log": AuditLog,
        }
        if key not in expected:
            raise KeyError(key)
        if not isinstance(value, expected[key]):
            raise TypeError(f"Invalid value for {key}")
        setattr(self, key, value)
