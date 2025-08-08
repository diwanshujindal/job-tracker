import imaplib

host = 'imap.gmail.com'
user = 'your-email@gmail.com'
password = 'your-app-password'

M = imaplib.IMAP4_SSL(host)
M.login(user, password)

typ, mailboxes = M.list()
print('Mailboxes:', mailboxes)

# Try multiple mailboxes here based on output
M.select('INBOX')
typ, data = M.search(None, 'ALL')
print('INBOX messages count:', len(data[0].split()))

M.select('"[Gmail]/All Mail"')
typ, data = M.search(None, 'ALL')
print('[Gmail]/All Mail messages count:', len(data[0].split()))

M.logout()
