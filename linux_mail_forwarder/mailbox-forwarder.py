#!/usr/bin/env python3

import smtplib
import sys
from email.message import EmailMessage
from sys import argv
import mailbox
from typing import List, Optional
from tempfile import mkstemp

import gnupg
from dotenv import load_dotenv
from socket import gethostname
import os
import shutil

# Load environment variables from .env file
load_dotenv()

# Initialize GnuPG
gpg = gnupg.GPG()

# Load variables from .env file
smtp_server = os.getenv('SMTP_SERVER')
smtp_port = int(os.getenv('SMTP_PORT') or "465")  # Ensure this is an integer
smtp_user = os.getenv('SMTP_USER')
smtp_password = os.getenv('SMTP_PASSWORD')
from_address = smtp_user
to_address = os.getenv('TO_ADDRESS')

assert smtp_server
assert smtp_port
assert smtp_user
assert smtp_password
assert from_address
assert to_address

# Path to the mailbox file
try:
    mailbox_path = argv[1]
except IndexError:
    print(f"Usage: {argv[0]} mailbox_path", file=sys.stderr)
    exit(1)


def forward_email(msg: mailbox.mboxMessage) -> bool:
    """
    Encrypt and forward the given email message using the SMTP server.
    """
    # Encrypt the email content with the recipient's public key
    # noinspection PyTypeChecker
    encrypted_content = gpg.encrypt(msg.get_payload(), recipients=[to_address], always_trust=True, armor=True)
    # noinspection PyTypeChecker
    encrypted_mail = gpg.encrypt(msg.as_bytes(), recipients=[to_address], always_trust=True, armor=True)

    if not encrypted_content.ok:
        print(f"[!] Encryption failed: {encrypted_content.status}", file=sys.stderr)
        return False

    try:
        with smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=30) as server:
            server.login(smtp_user, smtp_password)

            # Create a new EmailMessage for forwarding, with encrypted content
            forward_msg = EmailMessage()
            forward_msg.set_content(str(encrypted_content))

            forward_msg.add_attachment(
                encrypted_mail.data,
                filename="original_message.eml.asc",
                maintype="application",
                subtype="pgp-encrypted"
            )

            # Set the headers for forwarding
            forward_msg['Subject'] = f"[DEV] [{gethostname()}] {msg.get('subject', 'No Subject')}"
            forward_msg['From'] = from_address
            forward_msg['To'] = to_address
            print('[*] Forwarding', forward_msg['Subject'])

            # Send the email
            server.send_message(forward_msg)
            return True
    except smtplib.SMTPException as e:
        print(f'[!] SMTP error occurred: {e}', file=sys.stderr)
        return False


def main() -> int:
    mbox: Optional[mailbox.mbox] = None
    _, mbox_tmp_path = mkstemp()
    try:
        # Open the mailbox
        mbox = mailbox.mbox(mailbox_path)
        mbox.lock()  # Lock the mailbox to make changes

        # Copy to temporary file as to overcome permission denied error
        shutil.copy(mailbox_path, mbox_tmp_path)
        mbox_tmp = mailbox.mbox(mbox_tmp_path)

        # Iterate over all messages in the mailbox and forward them
        to_remove: List[str] = []
        for key, msg in mbox_tmp.iteritems():
            if forward_email(msg):
                to_remove.append(key)

        for key in to_remove:
            mbox_tmp.remove(key)  # Mark the message for deletion

        mbox_tmp.flush()  # Commit changes and delete marked messages
        shutil.copy(mbox_tmp_path, mailbox_path)
    except FileNotFoundError:
        print(f"[!] The file {mailbox_path} does not exist.", file=sys.stderr)
        return 1
    except PermissionError as e:
        print(f"[!] Permission denied when trying to access {mailbox_path} ({e}).", file=sys.stderr)
        return 2
    finally:
        if mbox is not None:
            mbox.unlock()
        if os.path.exists(mbox_tmp_path):
            os.unlink(mbox_tmp_path)

    print("[*] Everything done")
    return 0


if __name__ == '__main__':
    exit(main())
