#!/usr/bin/env python3

import smtplib
from email.message import EmailMessage
import mailbox
import gnupg
from dotenv import load_dotenv
from socket import gethostname
import os

# Load environment variables from .env file
load_dotenv()

# Initialize GnuPG
gpg = gnupg.GPG()

# Load variables from .env file
smtp_server = os.getenv('SMTP_SERVER')
smtp_port = int(os.getenv('SMTP_PORT'))  # Ensure this is an integer
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
mailbox_path = '/var/mail/adam'


def forward_email(msg: mailbox.mboxMessage) -> bool:
    """
    Encrypt and forward the given email message using the SMTP server.
    """
    # Encrypt the email content with the recipient's public key
    # noinspection PyTypeChecker
    encrypted_data = gpg.encrypt(msg.get_payload(), recipients=[to_address], always_trust=True)

    if not encrypted_data.ok:
        print(f"Encryption failed: {encrypted_data.status}")
        return False

    with smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=30) as server:
        server.login(smtp_user, smtp_password)

        # Create a new EmailMessage for forwarding, with encrypted content
        forward_msg = EmailMessage()
        forward_msg.set_content(str(encrypted_data))

        # Set the headers for forwarding
        forward_msg['Subject'] = f"[DEV] [{gethostname()}] {msg.get('subject', 'No Subject')}"
        forward_msg['From'] = from_address
        forward_msg['To'] = to_address
        print('[*] forwarding', forward_msg['Subject'])

        # Send the email
        server.send_message(forward_msg)
        return True


def main() -> int:
    try:
        # Open the mailbox
        mbox = mailbox.mbox(mailbox_path)

        # Iterate over all messages in the mailbox and forward them
        for msg in mbox:
            forward_email(msg)
            print("Email forwarded successfully.")
    except FileNotFoundError:
        print(f"The file {mailbox_path} does not exist.")
        return 1
    except PermissionError:
        print(f"Permission denied when trying to access {mailbox_path}.")
        return 2
    return 0


if __name__ == '__main__':
    exit(main())
