import imaplib
import email
from email.header import decode_header

HOST = 'imap.gmail.com'    # or your IMAP host
USER = 'diwanshujindal108@gmail.com'   # your email
PASSWORD = 'hyiz ight wzwv adhk'  # app password, not your normal password
MAILBOX = 'INBOX'   # or '[Gmail]/All Mail'

def simple_imap_test():
    try:
        M = imaplib.IMAP4_SSL(HOST)
        M.login(USER, PASSWORD)
        print("Login successful!")
        M.select(MAILBOX)
        typ, data = M.search(None, 'ALL')
        if typ != 'OK':
            print("No messages found.")
            return
        ids = data[0].split()
        print(f"Number of messages in {MAILBOX}: {len(ids)}")
        # Fetch and print subject of first 5 emails
        for num in ids[-5:]:
            typ, msg_data = M.fetch(num, '(RFC822)')
            if typ != 'OK':
                print(f"Failed to fetch message {num.decode()}")
                continue
            msg = email.message_from_bytes(msg_data[0][1])
            subject, encoding = decode_header(msg.get('Subject'))[0]
            if isinstance(subject, bytes):
                subject = subject.decode(encoding or 'utf-8', errors='ignore')
            print(f"Message {num.decode()}: {subject}")
        M.logout()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    simple_imap_test()
