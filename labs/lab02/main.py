from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta

from .task1 import Admin, AuditLog, User, UserAccount
from .task2 import main as analyze_main


def demo() -> None:
    print("=== TASK 1: OOP User and Account Model ===")
    user = User("student", "student_1@example.com")
    user.set_password("correct-password")
    account = UserAccount(user, audit_log=AuditLog())

    print("\n--- User and account demonstration ---")
    print(
        f"Successful login: {account.login('student', 'correct-password', '192.0.2.10')}"
    )
    print(f"Failed login: {account.login('student', 'wrong-password', '192.0.2.10')}")
    user.email = "student_2@example.com"
    print(f"Updated email: {user.email}")

    admin = Admin("admin", "admin_1@example.com", {"read_reports"})
    admin.grant_permission("manage_users")
    print(admin)

    if account.session is not None:
        account.session.last_activity = datetime.now(UTC) - timedelta(seconds=901)
    print(f"Authenticated after timeout: {account.is_authenticated()}")
    account.login("student", "correct-password", "192.0.2.10")
    account.logout()
    print("Audit records:")
    for record in account.audit_log.show_all():
        print(f"{record.timestamp.isoformat()} {record.username}: {record.action}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Laboratory work 2 utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("demo", help="run the OOP demonstration")
    for command, help_text in (
        ("analyze", "audit HTTP security headers"),
        ("all", "run both laboratory tasks"),
    ):
        command_parser = subparsers.add_parser(command, help=help_text)
        command_parser.add_argument("--headers-file", required=True)
        command_parser.add_argument("--output-csv", required=True)
        command_parser.add_argument("--strict", action="store_true")
        command_parser.add_argument(
            "--log-level",
            choices=("DEBUG", "INFO", "WARNING", "ERROR"),
            default="INFO",
        )
    return parser


def main(argv: list[str] | None = None) -> int:
    args, remaining = build_parser().parse_known_args(argv)
    if args.command == "demo":
        demo()
        return 0
    if args.command == "all":
        print("=== LABORATORY WORK 2 ===")
        print("--- Running both tasks ---\n")
        demo()
        print("\n" + "=" * 70 + "\n")
    return analyze_main(
        [
            "--headers-file",
            args.headers_file,
            "--output-csv",
            args.output_csv,
            "--log-level",
            args.log_level,
            *(["--strict"] if args.strict else []),
            *remaining,
        ]
    )


if __name__ == "__main__":
    raise SystemExit(main())
