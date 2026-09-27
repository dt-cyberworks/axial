"""Test-wide setup.

The MFA encryption key (REQ-IAM-004) no longer ships as a source default - a
real Fernet key must come from the environment (app default is now empty). Tests
that enroll/verify TOTP need a valid key, so generate one per session here. It is
created in-process, never leaves the test run, and is not a real credential.
"""

import os

from cryptography.fernet import Fernet

os.environ.setdefault("MFA_ENCRYPTION_KEY", Fernet.generate_key().decode())
"""(setdefault so an explicit MFA_ENCRYPTION_KEY in the environment still wins.)"""

# GitHub issue #25: same reasoning as MFA_ENCRYPTION_KEY above, but a
# DISTINCT generated key - tests that set/read an LLM or NVD provider API
# key need a valid SETTINGS_ENCRYPTION_KEY.
os.environ.setdefault("SETTINGS_ENCRYPTION_KEY", Fernet.generate_key().decode())
