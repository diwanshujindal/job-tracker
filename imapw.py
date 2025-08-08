import imaplib

host = 'imap.gmail.com'
user = 'diwanshujindal108@gmail.com'           # Replace with your Gmail address
password = 'hyiz ight wzwv adhk'          # Replace with your Gmail App Password

try:
    M = imaplib.IMAP4_SSL(host)
    M.login(user, password)
    print("Login successful!")

    typ, mailboxes = M.list()
    if typ == 'OK':
        print("Available mailboxes:")
        for m in mailboxes:
            print(m.decode() if isinstance(m, bytes) else m)
    else:
        print("Failed to list mailboxes")

    M.select('INBOX')
    typ, data = M.search(None, 'ALL')
    if typ == 'OK':
        print(f"Number of messages in INBOX: {len(data[0].split())}")
    else:
        print("Failed to search INBOX")

    M.logout()
except imaplib.IMAP4.error as e:
    print("IMAP error:", e)
except Exception as e:
    print("Error:", e)
