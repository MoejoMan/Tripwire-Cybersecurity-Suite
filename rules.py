"""
Canonical SSH info-line parsing rules.

Each rule provides:
- name: short identifier for the event type
- regex: compiled pattern with named groups `username` and `ip`
- success: whether the event indicates a successful authentication

Add new dicts to extend coverage for additional sshd messages.
"""
import re

PATTERNS = [
	{
		'name': 'invalid_user',
		'regex': re.compile(r"Invalid user (?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"),
		'success': False,
	},
	{
		'name': 'failed_password_user',
		'regex': re.compile(r"Failed password for (?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"),
		'success': False,
	},
	{
		'name': 'failed_password_invalid',
		'regex': re.compile(r"Failed password for invalid user (?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"),
		'success': False,
	},
	{
		'name': 'accepted_password',
		'regex': re.compile(r"Accepted password for (?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"),
		'success': True,
	},
	{
		'name': 'accepted_publickey',
		'regex': re.compile(r"Accepted publickey for (?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"),
		'success': True,
	},
	{
		'name': 'accepted_keyboard_interactive',
		'regex': re.compile(r"Accepted keyboard-interactive(?:/pam)? for (?P<username>\S+) from (?P<ip>[0-9a-fA-F:.]+)"),
		'success': True,
	},
]

