import sys
import sqlite3
import imaplib
import email
from email.header import decode_header
import re
from datetime import datetime
import csv

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTableWidget, QTableWidgetItem, QTextEdit, QMessageBox,
    QComboBox, QFileDialog, QSplitter, QHeaderView
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

DB_PATH = 'job_tracker.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS emails (
        id INTEGER PRIMARY KEY,
        msg_id TEXT UNIQUE,
        from_addr TEXT,
        subject TEXT,
        date TEXT,
        body TEXT
    )
    ''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS jobs (
        id INTEGER PRIMARY KEY,
        msg_id TEXT UNIQUE,
        company TEXT,
        role TEXT,
        date_applied TEXT,
        status TEXT,
        notes TEXT
    )
    ''')
    conn.commit()
    conn.close()

def upsert_email(msg_id, from_addr, subject, date, body):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT OR IGNORE INTO emails (msg_id, from_addr, subject, date, body)
                 VALUES (?, ?, ?, ?, ?)''', (msg_id, from_addr, subject, date, body))
    if c.rowcount == 1:
        print(f'DEBUG: Inserted email {msg_id}')
    else:
        print(f'DEBUG: Email {msg_id} already exists, skipping insert')
    conn.commit()
    conn.close()

def upsert_job(msg_id, company, role, date_applied, status):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT OR IGNORE INTO jobs (msg_id, company, role, date_applied, status)
                 VALUES (?, ?, ?, ?, ?)''', (msg_id, company, role, date_applied, status))
    if c.rowcount == 1:
        print(f'DEBUG: Inserted job {msg_id}')
    else:
        c.execute('''UPDATE jobs SET company = ?, role = ?, date_applied = ?, status = ?
                     WHERE msg_id = ?''', (company, role, date_applied, status, msg_id))
        print(f'DEBUG: Updated job {msg_id}')
    conn.commit()
    conn.close()

def get_all_jobs(filter_status=None, search_text=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    q = 'SELECT id, msg_id, company, role, date_applied, status, notes FROM jobs'
    params = []
    clauses = []
    if filter_status and filter_status != 'All':
        clauses.append('status = ?')
        params.append(filter_status)
    if search_text:
        clauses.append('(company LIKE ? OR role LIKE ? OR notes LIKE ?)')
        params.extend([f'%{search_text}%'] * 3)
    if clauses:
        q += ' WHERE ' + ' AND '.join(clauses)
    q += ' ORDER BY date_applied DESC'
    c.execute(q, params)
    rows = c.fetchall()
    conn.close()
    return rows

def get_email_by_msgid(msg_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT subject, from_addr, date, body FROM emails WHERE msg_id = ?', (msg_id,))
    r = c.fetchone()
    conn.close()
    return r

def update_job_status(job_id, new_status):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE jobs SET status = ? WHERE id = ?', (new_status, job_id))
    conn.commit()
    conn.close()

def export_jobs_csv(path):
    rows = get_all_jobs()
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Company','Role','Date Applied','Status','Notes'])
        for r in rows:
            writer.writerow([r[2], r[3], r[4], r[5], r[6] or ''])


STATUS_KEYWORDS = {
    'Applied': [r'thank you for applying', r'application submitted'],
    'Interview': [r'call with', r'interview invite'],
    'Offer': [r'we are pleased to offer'],
    'Rejected': [ r'not moving forward',  r'we regret to inform']
}

def classify_email(text):
    t = text.lower()
    for status, patterns in STATUS_KEYWORDS.items():
        for p in patterns:
            if re.search(p, t):
                return status
    return 'Applied'  

def extract_company(from_header):
    if '<' in from_header:
        name_part = from_header.split('<')[0].strip(' "')
        if name_part:
            return name_part
    m = re.search(r'@([\w\.-]+)', from_header)
    if m:
        domain = m.group(1)
        domain = domain.split('.')[-2] if '.' in domain else domain
        return domain.capitalize()
    return 'Unknown'

def extract_role(subject):
    sub = subject
    sub = re.sub(r'(?i)re:|fwd:','', sub)
    parts = re.split(r'[-:|\u2014]', sub)
    if len(parts) > 1:
        cand = parts[0].strip()
        m = re.search(r'for\s+(.+)', sub, re.I)
        if m:
            return m.group(1).strip()
        return parts[-1].strip()
    return subject.strip()

class ImapSyncThread(QThread):
    progress = pyqtSignal(str)
    finished = pyqtSignal(int)

    def __init__(self, host, email_user, password, mailbox='INBOX', limit=1000):
        super().__init__()
        self.host = host
        self.email_user = email_user
        self.password = password
        self.mailbox = mailbox
        self.limit = limit

    def run(self):
        try:
            self.progress.emit('Connecting to IMAP...')
            print('DEBUG: Connecting to IMAP...')
            M = imaplib.IMAP4_SSL(self.host)
            M.login(self.email_user, self.password)
            print('DEBUG: Login successful.')
            self.progress.emit('Selecting mailbox...')
            M.select(self.mailbox)
            self.progress.emit('Searching for messages...')
            typ, data = M.search(None, 'ALL')
            if typ != 'OK':
                self.progress.emit('No messages found')
                self.finished.emit(0)
                return
            ids = data[0].split()
            ids = ids[-self.limit:]
            print(f'DEBUG: Found {len(ids)} messages to process.')
            count = 0
            for num in ids:
                self.progress.emit(f'Fetching message id {num.decode()}...')
                typ, msg_data = M.fetch(num, '(RFC822)')
                if typ != 'OK':
                    self.progress.emit(f'Failed to fetch message id {num.decode()}')
                    continue
                msg = email.message_from_bytes(msg_data[0][1])
                msg_id = msg.get('Message-ID') or f'no-msgid-{num.decode()}'
                subject, encoding = decode_header(msg.get('Subject') or '')[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding or 'utf-8', errors='ignore')
                from_ = msg.get('From') or ''
                date_raw = msg.get('Date') or ''
                try:
                    date_obj = email.utils.parsedate_to_datetime(date_raw)
                    date_str = date_obj.isoformat()
                except Exception:
                    date_str = date_raw
                body = ''
                if msg.is_multipart():
                    for part in msg.walk():
                        ctype = part.get_content_type()
                        cdispo = str(part.get('Content-Disposition'))
                        if ctype == 'text/plain' and 'attachment' not in cdispo:
                            try:
                                body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
                                break
                            except:
                                continue
                else:
                    body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='ignore')

                print(f'DEBUG: msg_id={msg_id}, subject={subject}')
                self.progress.emit(f'Processing: {subject[:80]}')

                combined = f"{subject}\n{body}"
                status = classify_email(combined)
                company = extract_company(from_)
                role = extract_role(subject)

                upsert_email(msg_id, from_, subject, date_str, body)
                upsert_job(msg_id, company, role, date_str, status)
                count += 1
            M.logout()
            self.progress.emit('Done syncing')
            self.finished.emit(count)
        except imaplib.IMAP4.error as e:
            self.progress.emit(f'IMAP error: {e}')
            print(f'DEBUG: IMAP error: {e}')
            self.finished.emit(0)
        except Exception as e:
            self.progress.emit(f'Error: {e}')
            print(f'DEBUG: Error: {e}')
            self.finished.emit(0)

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Local Job Application Tracker')
        self.resize(1000, 600)
        init_db()
        self._build_ui()
        self.load_table()

    def _build_ui(self):
        layout = QVBoxLayout()

        settings_layout = QHBoxLayout()
        settings_layout.addWidget(QLabel('IMAP Host:'))
        self.host_input = QLineEdit('imap.gmail.com')
        settings_layout.addWidget(self.host_input)
        settings_layout.addWidget(QLabel('Email:'))
        self.email_input = QLineEdit('you@example.com')
        settings_layout.addWidget(self.email_input)
        settings_layout.addWidget(QLabel('App Password:'))
        self.pw_input = QLineEdit()
        self.pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        settings_layout.addWidget(self.pw_input)
        self.sync_btn = QPushButton('Sync')
        self.sync_btn.clicked.connect(self.start_sync)
        settings_layout.addWidget(self.sync_btn)
        layout.addLayout(settings_layout)

        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel('Status:'))
        self.status_filter = QComboBox()
        self.status_filter.addItems(['All','Applied','Interview','Offer','Rejected'])
        self.status_filter.currentIndexChanged.connect(self.load_table)
        filter_layout.addWidget(self.status_filter)
        filter_layout.addWidget(QLabel('Search:'))
        self.search_input = QLineEdit()
        self.search_input.textChanged.connect(self.load_table)
        filter_layout.addWidget(self.search_input)
        self.export_btn = QPushButton('Export CSV')
        self.export_btn.clicked.connect(self.export_csv)
        filter_layout.addWidget(self.export_btn)
        layout.addLayout(filter_layout)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(['ID','Company','Role','Date Applied','Status'])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.cellClicked.connect(self.table_clicked)
        splitter.addWidget(self.table)

        details_widget = QWidget()
        dv = QVBoxLayout()
        self.email_subject = QLabel('<subject>')
        dv.addWidget(self.email_subject)
        self.email_from = QLabel('<from>')
        dv.addWidget(self.email_from)
        self.email_date = QLabel('<date>')
        dv.addWidget(self.email_date)
        self.email_body = QTextEdit()
        self.email_body.setReadOnly(True)
        dv.addWidget(self.email_body)
        status_row = QHBoxLayout()
        status_row.addWidget(QLabel('Manual status:'))
        self.manual_status = QComboBox()
        self.manual_status.addItems(['Applied','Interview','Offer','Rejected'])
        status_row.addWidget(self.manual_status)
        self.save_status_btn = QPushButton('Save Status')
        self.save_status_btn.clicked.connect(self.save_status)
        status_row.addWidget(self.save_status_btn)
        dv.addLayout(status_row)
        details_widget.setLayout(dv)
        splitter.addWidget(details_widget)

        layout.addWidget(splitter)

        self.progress_label = QLabel('Ready')
        layout.addWidget(self.progress_label)

        self.setLayout(layout)

    def start_sync(self):
        host = self.host_input.text().strip()
        user = self.email_input.text().strip()
        pw = self.pw_input.text().strip()
        if not host or not user or not pw:
            QMessageBox.warning(self, 'Missing info', 'Please fill IMAP host, email and app password.')
            return
        self.sync_btn.setEnabled(False)
        self.thread = ImapSyncThread(host, user, pw)
        self.thread.progress.connect(self.on_progress)
        self.thread.finished.connect(self.on_finished)
        self.thread.start()

    def on_progress(self, msg):
        self.progress_label.setText(msg)
        print(f'PROGRESS: {msg}')

    def on_finished(self, count):
        self.progress_label.setText(f'Sync finished. Processed {count} messages.')
        print(f'PROGRESS: Sync finished. Processed {count} messages.')
        self.sync_btn.setEnabled(True)
        self.load_table()

    def load_table(self):
        status = self.status_filter.currentText()
        search = self.search_input.text().strip()
        rows = get_all_jobs(filter_status=status, search_text=search)
        self.table.setRowCount(0)
        for r in rows:
            row_pos = self.table.rowCount()
            self.table.insertRow(row_pos)
            self.table.setItem(row_pos, 0, QTableWidgetItem(str(r[0])))
            self.table.setItem(row_pos, 1, QTableWidgetItem(r[2]))
            self.table.setItem(row_pos, 2, QTableWidgetItem(r[3]))
            self.table.setItem(row_pos, 3, QTableWidgetItem(r[4]))
            self.table.setItem(row_pos, 4, QTableWidgetItem(r[5]))

    def table_clicked(self, row, col):
        id_item = self.table.item(row, 0)
        if not id_item:
            return
        job_id = int(id_item.text())
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT msg_id, company, role, date_applied, status, notes FROM jobs WHERE id = ?', (job_id,))
        r = c.fetchone()
        conn.close()
        if not r:
            return
        msg_id = r[0]
        subj, from_addr, date_str, body = get_email_by_msgid(msg_id) or ('<no subject>','<no from>','<no date>','<no body>')
        self.email_subject.setText(f'<b>{subj}</b>')
        self.email_from.setText(f'From: {from_addr}')
        self.email_date.setText(f'Date: {date_str}')
        self.email_body.setPlainText(body or '')
        self.current_job_id = job_id
        self.manual_status.setCurrentText(r[4])

    def save_status(self):
        if not hasattr(self, 'current_job_id'):
            return
        new_status = self.manual_status.currentText()
        update_job_status(self.current_job_id, new_status)
        self.load_table()
        QMessageBox.information(self, 'Saved', 'Status updated.')

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Export CSV', '', 'CSV files (*.csv)')
        if not path:
            return
        export_jobs_csv(path)
        QMessageBox.information(self, 'Exported', f'Exported to {path}')

if __name__ == '__main__':
    print("Starting Job Tracker app...")
    app = QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())
