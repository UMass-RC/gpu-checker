"""
Simon Leary
6/30/2022
GPU Checker
Loops with `sinfo` over nodes that are in both STATES_TO_CHECK and PARTITIONS_TO_CHECK
ssh's in using SSH_USER and SSH_PRIVKEY_FQN, tries to run `nvidia-smi`
If that fails in any way, send an email to EMAIL_TO from EMAIL_FROM (and put the node in DRAINING state)***
It actually sends two emails - one that there's an error and another that it's being put into DRAINING

gpu_checker_config.ini contains a cleartext password
    should be excluded from source control!
    should not be readable by any other user!
"""
import subprocess
import time
import smtplib
from email.message import EmailMessage
import configparser
import os
import re
from typing import Tuple
import logging
from logging.handlers import RotatingFileHandler
import sys
import traceback

CONFIG = None
LOG = None

def str_to_bool(string) -> bool:
    if string.lower() in ['true', '1', 't', 'y', 'yes']:
        return True
    if string.lower() in ['false', '0', 'f', 'n', 'no']:
        return False
    return None

def indent(string: str, n=1) -> str:
    for i in range(n):
        string = '\t' + string # add tab to first line
        string = string.replace('\n', '\n\t') # add tab to all other lines
    return string

def multiline_str(*argv: str) -> str:
    """
    concat the strings and separate them with newlines
    with no indentation funny business!
    """
    string = ''
    for arg in argv:
        string = string + str(arg) + '\n'
    string = string[0:-1] # remove final newline
    return string

def remove_empty_lines(string: str) -> str:
    return os.linesep.join([line for line in string.splitlines() if line])

def purge_element(_list: list, elem_to_purge) -> list:
    return [elem for elem in _list if elem != elem_to_purge]

def logger_init(info_filename='gpu_checker.log', error_filename='gpu_checker_error.log',
                max_filesize_MB=1024, backup_count=1, do_print=True,
                name='gpu_checker') -> logging.Logger:
    """
    creates up to 4 log files, each up to size max_filesize_MB
        info_filename
        info_filename.1 (backup)
        error_filename
        error_filename.1 (backup)
    """
    log = logging.getLogger(name)

    if do_print:
        stream_handler = logging.StreamHandler()
        log.addHandler(stream_handler)

    file_handler_info = RotatingFileHandler(
        info_filename,
        mode='w',
        maxBytes=max_filesize_MB*1024,
        backupCount=backup_count)
    file_handler_info.setLevel(logging.INFO)
    log.addHandler(file_handler_info)

    file_handler_error = RotatingFileHandler(
        error_filename,
        mode='w',
        maxBytes=max_filesize_MB*1024,
        backupCount=backup_count)
    file_handler_error.setLevel(logging.ERROR)
    log.addHandler(file_handler_error)

    log.setLevel(logging.INFO)
    return log

class ShellRunner:
    """
    spawn this with a shell command, then you have access to stdout, stderr, exit code,
    along with a boolean of whether or not the command was a success (exit code 0)
    and if you use str(your_shell_runner), you get a formatted report of all the above
    """
    def __init__(self, command):
        process = subprocess.run(
            command,
            capture_output=True,
            shell=True
        )
        # process.std* returns a bytes object, convert to string
        self.shell_output = remove_empty_lines(str(process.stdout, 'UTF-8'))
        self.shell_error = remove_empty_lines(str(process.stderr, 'UTF-8'))
        self.exit_code = process.returncode
        self.success = self.exit_code == 0
        self.command_report = multiline_str(
            "command:",
            indent(command),
            f"exit code: {self.exit_code}",
            '',
            "stdout:",
            indent(self.shell_output),
            '',
            "stderr:",
            indent(self.shell_error),
        )
    def __str__(self):
        return self.command_report

def find_slurm_nodes(partitions: str) -> None:
    """"
    return a list of node names that are in the specified partitions
    partitions is a comma delimited string
    """
    command = f"sinfo --partition={partitions} -N --noheader"
    command_results = ShellRunner(command)
    success = command_results.success
    shell_output = command_results.shell_output
    command_report = str(command_results)

    if not success:
        raise Exception(command_report) # barf

    nodes = [line.split(' ')[0] for line in shell_output.splitlines()]
    if len(nodes) == 0:
        raise Exception(f"no nodes found! `{command}`")

    return nodes

def do_check_node(node: str):
    """
    do I want to check this node? Based on node states, states_to_check and states_not_to_check
    if a node has at least one state_to_check, then check
    unless it has any state_not_to_check, then instant return False
    """
    do_check = False
    states_to_check = CONFIG['nodes']['states_to_check'].split(',')
    states_not_to_check = CONFIG['nodes']['states_not_to_check'].split(',')

    command_results = ShellRunner(f"scontrol show node {node}")
    command_output = command_results.shell_output
    if re.match(r"Node (\S+) not found", command_output):
        return False
    # scontrol has states delimited by '+'
    states = re.search(r"State=(\S*)", command_output).group(1).split('+')
    for state in states:
        for bad_state in states_not_to_check:
            if state.lower() == bad_state.lower():
                return False
        for good_state in states_to_check:
            if state.lower() == good_state.lower():
                do_check = True
    return do_check

def drain_node(node: str, reason: str) -> Tuple[bool, str]:
    """"
    tell slurm to put specified node into DRAINING state
    returns True if it works, false if it doesn't
    also returns formatted report of the operation
    """
    command_results = ShellRunner(f"scontrol update nodename={node} state=drain reason=\"{reason}\"")
    success = command_results.success
    command_report = str(command_results)
    return success, command_report

def check_gpu(node: str) -> Tuple[bool, str]:
    """
    ssh into node and run `nvidia-smi`
    returns True if it works, false if it doesn't
    also returns formatted report of the operation
    """
    ssh_user = CONFIG['ssh']['user']
    ssh_privkey = CONFIG['ssh']['keyfile']
    command = f"ssh {ssh_user}@{node} -o \"StrictHostKeyChecking=no\" -i {ssh_privkey} nvidia-smi && echo $? || echo $?"
    command_results = ShellRunner(command)

    command_report = str(command_results)
    ssh_exit_code = command_results.shell_output.splitlines()[-1]
    success = command_results.success and int(ssh_exit_code) == 0
    return success, command_report

def send_email(to: str, _from: str, subject: str, body: str) -> None:
    """
    send an email using an SMTP server on localhost
    """
    body = multiline_str(
        body,
        '',
        CONFIG['email']['signature']
    )
    logging.error(multiline_str(
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

    hostname = CONFIG['smtp_auth']['smtp_hostname']
    port = int(CONFIG['smtp_auth']['smtp_port'])
    user = CONFIG['smtp_auth']['smtp_user']
    password = CONFIG['smtp_auth']['smtp_password']
    is_ssl = str_to_bool(CONFIG['smtp_auth']['smtp_is_ssl'])

    if is_ssl:
        s = smtplib.SMTP_SSL(hostname, port, timeout=5)
    else:
        s = smtplib.SMTP(hostname, port, timeout=5)
    s.login(user, password)
    s.send_message(msg)
    s.quit()

    logging.info("email sent successfully!____________________________________________________")

if __name__=="__main__":
    CONFIG = configparser.ConfigParser()
    if os.path.isfile('gpu_checker_config.ini'):
        CONFIG.read('gpu_checker_config.ini')
    else:
        # write default empty config file
        CONFIG['nodes'] = {
            "states_to_check" : "mixed,idle",
            "states_not_to_check" : "drain",
            "partitions_to_check" : "gpu"
        }
        CONFIG['ssh'] = {
            "user" : "",
            "keyfile" : ""
        }
        CONFIG['email'] = {
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
        CONFIG['logger'] = {
            "info_filename" : "gpu_checker.log",
            "error_filename" : "gpu_checker_error.log",
            "max_filesize_MB" : "1024",
            "backup_count" : "1"
        }
        with open('gpu_checker_config.ini', 'w', encoding='utf-8') as config_file:
            CONFIG.write(config_file)

    LOG = logger_init(CONFIG['logger']['info_filename'], CONFIG['logger']['error_filename'],
        int(CONFIG['logger']['max_filesize_MB']), int(CONFIG['logger']['backup_count']))
    # global exception handler write to log file
    def my_excepthook(exc_type, exc_value, exc_traceback):
        exc_lines = traceback.format_exception(exc_type, "", exc_traceback)
        exc_lines = [line.strip() for line in exc_lines]
        for line in exc_lines:
            LOG.error(line)
        LOG.error(exc_value)
    sys.excepthook = my_excepthook

    states = CONFIG['nodes']['states_to_check']
    partitions = CONFIG['nodes']['partitions_to_check']
    do_send_email = str_to_bool(CONFIG['email']['enabled'])

    while True:
        for node in find_slurm_nodes(partitions):
            #logging.info(node, do_check_node(node))
            if do_check_node(node):
                gpu_works, check_report = check_gpu(node)
                if gpu_works:
                    logging.info(f"{node} works")
                    continue
                # if not gpu_works:
                drain_success, drain_report = drain_node(node, 'nvidia-smi failure')
                if do_send_email:
                    full_report = multiline_str(
                        "gpu check:",
                        indent(check_report),
                        '',
                        "drain operation:",
                        indent(drain_report)
                    )
                    subject = f"gpu-checker has found an error on {node}"
                    if not drain_success:
                        subject = subject + " and FAILED to drain the node"

                    email_to = CONFIG['email']['to']
                    email_from = CONFIG['email']['from']
                    send_email(
                        email_to,
                        email_from,
                        subject,
                        full_report
                    )
            # each loop takes about 5 seconds on its own, most of the delay is the ssh command
                time.sleep(60)
