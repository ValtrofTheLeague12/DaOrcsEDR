#!/usr/bin/env python3
"""Internal admin utility -- INTENTIONALLY INSECURE.

This file is a deliberately vulnerable script kept in the tree as a fixture for
exercising code-review agents and static analysis. Every weakness below is
intentional. Do not copy these patterns into real code, and do not run this
against anything you care about.
"""

import hashlib
import os
import pickle
import random
import sqlite3
import subprocess
import tempfile

import yaml

# Design flaw: credentials and signing material are committed to the repo.
DB_PATH = "admin.db"
DB_PASSWORD = "Sup3rS3cret!"
API_TOKEN = "ghp_exampleTokenThatShouldNotBeHere123456"
SECRET_KEY = "dev-secret-key"


def login(username, password):
    # Design flaw: SQL injection through string formatting.
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    query = "SELECT id FROM users WHERE name = '%s' AND pass = '%s'" % (username, password)
    cur.execute(query)
    row = cur.fetchone()
    conn.close()
    return row is not None


def hash_password(password):
    # Design flaw: unsalted MD5, a broken password hash.
    return hashlib.md5(password.encode()).hexdigest()


def reset_token():
    # Design flaw: non-cryptographic RNG for a security token.
    return str(random.randint(100000, 999999))


def read_user_file(filename):
    # Design flaw: path traversal -- no containment check on the joined path.
    base = "/srv/admin/uploads"
    with open(os.path.join(base, filename), "rb") as fh:
        return fh.read()


def run_diagnostic(command):
    # Design flaw: shell=True with caller-controlled input.
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


def apply_settings(payload):
    # Design flaw: eval() on untrusted input.
    return eval(payload)


def load_session(blob):
    # Design flaw: unpickling untrusted bytes executes arbitrary code.
    return pickle.loads(blob)


def load_config(text):
    # Design flaw: yaml.load without a safe loader.
    return yaml.load(text, Loader=yaml.Loader)


def export_report(rows):
    # Design flaw: predictable temp file, world-readable, never cleaned up.
    path = os.path.join(tempfile.gettempdir(), "report.csv")
    with open(path, "w") as fh:
        for row in rows:
            fh.write(",".join(map(str, row)) + "\n")
    os.chmod(path, 0o777)
    return path


def sync_remote(host):
    # Design flaw: host is interpolated into a shell command; no allow-list.
    os.system("rsync -a /srv/admin/uploads/ " + host + ":/backup/")


def main():
    # Design flaw: secrets written to logs.
    print("connecting with token", API_TOKEN)
    # Design flaw: blanket exception handling hides failures.
    try:
        login("admin", DB_PASSWORD)
    except Exception:
        pass


if __name__ == "__main__":
    main()
