#!/usr/bin/env python3

import smtplib
from email.message import EmailMessage
import mailbox
import gnupg
from dotenv import load_dotenv
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
recipient_key_id = os.getenv('RECIPIENT_KEY_ID')
from_address = smtp_user
to_address = os.getenv('TO_ADDRESS')

# Path to the mailbox file
mailbox_path = '/var/mail/root'


def forward_email(msg):
    """
    Encrypt and forward the given email message using the SMTP server.
    """
    # Encrypt the email content with the recipient's public key
    encrypted_data = gpg.encrypt(msg.get_payload(), recipients=[recipient_key_id], always_trust=True)

    if not encrypted_data.ok:
        print(f"Encryption failed: {encrypted_data.status}")
        return

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()  # Start TLS encryption
        server.login(smtp_user, smtp_password)

        # Create a new EmailMessage for forwarding, with encrypted content
        forward_msg = EmailMessage()
        forward_msg.set_content(str(encrypted_data))

        # Set the headers for forwarding
        forward_msg['Subject'] = f"Fwd: {msg.get('subject', 'No Subject')}"
        forward_msg['From'] = from_address
        forward_msg['To'] = to_address

        # Send the email
        server.send_message(forward_msg)


try:
    # Open the mailbox
    mbox = mailbox.mbox(mailbox_path)

    # Iterate over all messages in the mailbox and forward them
    for msg in mbox:
        forward_email(msg)
        print("Email forwarded successfully.")
except FileNotFoundError:
    print(f"The file {mailbox_path} does not exist.")
except PermissionError:
    print(f"Permission denied when trying to access {mailbox_path}.")
except Exception as e:
    print(f"An error occurred: {e}")
