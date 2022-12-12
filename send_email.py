#!/usr/bin/env python3
CONFIG_PREPEND = """
# CONFIG_FILE_NAME contains a cleartext password
#     should be excluded from source control!
#     should not be readable by any other user!
"""

import smtplib
from email.message import EmailMessage
import configparser
import os
import sys


CONFIG_FILE_NAME="gpu_checker_wrapper_email.ini"
USAGE = """usage:
python send_email.py 'SUBJECT' < bodyfilename
echo "BODY" | python send_email.py 'SUBJECT'
"""

def multiline_str(*argv: str) -> str:
    """
    a string with one line per argument
    """
    return os.linesep.join(argv)

def purge_element(_list: list, elem_to_purge) -> list:
    return [elem for elem in _list if elem != elem_to_purge]

def parse_multiline_config_list(string: str) -> list:
    """
    delete newlines, split by commas, strip each string, remove empty strings
    """
    return purge_element([state.strip() for state in string.replace('\n', '').split(',')], '')

def str_to_bool(string: str) -> bool:
    if string.lower() in ['true', '1', 't', 'y', 'yes']:
        return True
    if string.lower() in ['false', '0', 'f', 'n', 'no']:
        return False
    raise Exception(f"Can't convert {string} to boolean")

def send_email(to: str, _from: str, subject: str, body: str, signature: str,
               hostname: str, port: int, user: str, password: str, is_ssl: bool) -> None:
    body = multiline_str(
        body,
        '',
        signature
    )
    print(multiline_str(
        "sending email:_______________________________________________________________",
        f"to: {to}",
        f"from: {_from}",
        f"subject: {subject}",
        "body:",
        body,
    ))
    msg = EmailMessage()
    msg.set_content(body)
    msg['To'] = to
    msg['From'] = _from
    msg['Subject'] = subject

    if is_ssl:
        smtp = smtplib.SMTP_SSL(hostname, port, timeout=5)
    else:
        smtp = smtplib.SMTP(hostname, port, timeout=5)
    smtp.login(user, password)
    smtp.send_message(msg)
    smtp.quit()

    print("email sent successfully!____________________________________________________")

def init_config():
    config = configparser.ConfigParser()
    if os.path.isfile(CONFIG_FILE_NAME):
        config.read(CONFIG_FILE_NAME)
    else:
        print(f"config file not found. Creating new one at {CONFIG_FILE_NAME}")
        config['email'] = {
            "enabled" : "False",
            "to" : "",
            "from" : "",
            "signature" : "",
            "smtp_server" : "",
            "smtp_port" : "",
            "smtp_user" : "",
            "smtp_password" : "",
            "smtp_is_ssl" : "False"
        }
        with open(CONFIG_FILE_NAME, 'w', encoding='utf-8') as config_file:
            config_file.write(CONFIG_PREPEND)
            config.write(config_file)
        os.chmod(CONFIG_FILE_NAME, 0o600) # 0o means octal digits
        raise SystemExit()
    return config

if __name__=="__main__":
    config = init_config()

    if sys.stdin.isatty():
        print("contents of email body must be piped through stdin!")
        print(USAGE)
        raise SystemExit

    if len(sys.argv)==1:
        print("not enough arguments!")
        print(USAGE)
        raise SystemExit

    if len(sys.argv)>2:
        print("too many arguments!")
        print(USAGE)
        raise SystemExit

    send_email(
        config['email']['to'],
        config['email']['from'],
        sys.argv[1],
        sys.stdin.read(),
        config['email']['signature'],
        config['email']['smtp_server'],
        int(config['email']['smtp_port']),
        config['email']['smtp_user'],
        config['email']['smtp_password'],
        str_to_bool(config['email']['smtp_is_ssl'])
    )