"""
Simon Leary
6/30/2022
GPU Checker
"""
CONFIG_PREPEND = """
# gpu_checker_config.ini contains a cleartext password
#     should be excluded from source control!
#     should not be readable by any other user!
"""
import subprocess
import time
import smtplib
from email.message import EmailMessage
import configparser
import os
import re
from typing import Tuple
from typing import List
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
    return '\n'.join(argv)

def remove_empty_lines(string: str) -> str:
    return os.linesep.join([line for line in string.splitlines() if line])

def append_no_dupes(_list: list, elem) -> list:
    if elem not in _list:
        _list.append(elem)
    return _list

def purge_element(_list: list, elem_to_purge) -> list:
    return [elem for elem in _list if elem != elem_to_purge]

def purge_str(_list: List[str], str_to_purge, case_sensitive=True) -> list:
    """
    purge a string from a list
    converts list elements to string and does logic with that
    strips both the list elements and str_to_purge before comparing
    """
    if case_sensitive:
        return [elem for elem in _list if str(elem).strip() != str_to_purge.strip()]
    else:
        return [elem for elem in _list if str(elem).lower().strip() != str_to_purge.lower().strip()]

def parse_multiline_config_list(string: str):
    return [state.strip() for state in string.replace('\n', '').split(',')]

def logger_init(info_filename='gpu_checker.log', error_filename='gpu_checker_error.log',
                max_filesize_megabytes=1024, backup_count=1, do_print=True,
                name='gpu_checker') -> logging.Logger:
    """
    creates up to 4 log files, each up to size max_filesize_megabytes
        info_filename
        info_filename.1 (backup)
        error_filename
        error_filename.1 (backup)
    """
    log = logging.getLogger(name)
    log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')

    if do_print:
        stream_handler = logging.StreamHandler()
        log.addHandler(stream_handler)

    file_handler_info = RotatingFileHandler(
        info_filename,
        mode='w',
        maxBytes=max_filesize_megabytes*1024,
        backupCount=backup_count)
    file_handler_info.setFormatter(log_formatter)
    file_handler_info.setLevel(logging.INFO)
    log.addHandler(file_handler_info)

    file_handler_error = RotatingFileHandler(
        error_filename,
        mode='w',
        maxBytes=max_filesize_megabytes*1024,
        backupCount=backup_count)
    file_handler_error.setFormatter(log_formatter)
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

def find_slurm_nodes(partitions: str, include_nodes=[]) -> None:
    """"
    return a list of node names that are in the specified partitions
    partitions is a slurm formatted list (comma separated with extra options)
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

    for include_node in include_nodes:
        append_no_dupes(nodes, include_node)

    return purge_str(nodes, '')

def do_check_node(node: str, states_to_check: list, states_not_to_check: list,
                  include_nodes=[], exclude_nodes=[], do_log=True):
    """
    do I want to check this node?
    read the readme
    """
    do_check = False
    reasons = []
    command_results = ShellRunner(f"scontrol show node {node}")
    command_output = command_results.shell_output
    if re.match(r"Node (\S+) not found", command_output):
        return False
    # scontrol has states delimited by '+'
    states = re.search(r"State=(\S*)", command_output).group(1).split('+')
    do_break = False
    for state in states:
        if do_break:
            break
        for include_node in include_nodes:
            if node.lower() == include_node.lower():
                do_check = True
                reasons.append("listed in include_nodes")
                do_break = True # nested break
                break
        for exclude_node in exclude_nodes:
            if node.lower() == exclude_node.lower():
                do_check = False
                reasons.append("listed in exclude_nodes")
                do_break = True # nested break
                break
        for good_state in states_to_check:
            if state.lower() == good_state.lower():
                do_check = True
                reasons.append(good_state)
        for bad_state in states_not_to_check:
            if state.lower() == bad_state.lower():
                do_check = False
                reasons = [bad_state] # remove any other reasons listed, only this one matters
                do_break = True # nested break
                break
    if do_log:
        if len(reasons) == 0:
            reasons = ["no relevant states"]
        reasons_str = ','.join(reasons)
        LOG.info(f"checking node {node}?\t{do_check} because {reasons_str}")
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
    command = f"ssh {ssh_user}@{node} -o \"StrictHostKeyChecking=no\" -i {ssh_privkey} \'nvidia-smi ; echo $?\'"
    command_results = ShellRunner(command)

    command_report = str(command_results)

    # if ssh fails, don't report a bad gpu, raise an excpetion because unable to test
    if not command_results.success:
        raise Exception(command_report)

    ssh_exit_code = int(command_results.shell_output.splitlines()[-1].strip())
    success = (ssh_exit_code == 0)
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
    LOG.error(multiline_str(
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

    hostname = CONFIG['email']['smtp_server']
    port = int(CONFIG['email']['smtp_port'])
    user = CONFIG['email']['smtp_user']
    password = CONFIG['email']['smtp_password']
    is_ssl = str_to_bool(CONFIG['email']['smtp_is_ssl'])

    if is_ssl:
        smtp = smtplib.SMTP_SSL(hostname, port, timeout=5)
    else:
        smtp = smtplib.SMTP(hostname, port, timeout=5)
    smtp.login(user, password)
    smtp.send_message(msg)
    smtp.quit()

    LOG.info("email sent successfully!____________________________________________________")

if __name__=="__main__":
    CONFIG = configparser.ConfigParser()
    if os.path.isfile('gpu_checker_config.ini'):
        CONFIG.read('gpu_checker_config.ini')
    else:
        # write default empty config file
        CONFIG['nodes'] = {
            "states_to_check" : "allocated,mixed,idle",
            "states_not_to_check" : "drain",
            "partitions_to_check" : "gpu",
            "include_nodes" : "",
            "exclude_nodes" : ""
        }
        CONFIG['ssh'] = {
            "user" : "root",
            "keyfile" : "/root/.ssh/id_rsa"
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
            "max_filesize_megabytes" : "100",
            "backup_count" : "1"
        }
        CONFIG['misc'] = {
            "post_check_wait_time_s" : "60",
            "misc" : "do_drain_nodes"
        }
        with open('gpu_checker_config.ini', 'w', encoding='utf-8') as config_file:
            config_file.write(CONFIG_PREPEND)
            CONFIG.write(config_file)
        os.chmod('gpu_checker_config.ini', 0o700)

    print(CONFIG['nodes']['states_to_check'])


    LOG = logger_init(CONFIG['logger']['info_filename'], CONFIG['logger']['error_filename'],
        int(CONFIG['logger']['max_filesize_megabytes']), int(CONFIG['logger']['backup_count']))
    LOG.info("hello, world!")
    # global exception handler write to log file
    def my_excepthook(exc_type, exc_value, exc_traceback):
        exc_lines = traceback.format_exception(exc_type, "", exc_traceback)
        exc_lines = [line.strip() for line in exc_lines]
        for line in exc_lines:
            LOG.error(line)
        LOG.error(exc_value)
        sys.exit()
    sys.excepthook = my_excepthook

    do_send_email = str_to_bool(CONFIG['email']['enabled'])
    post_check_wait_time_s = int(CONFIG['misc']['post_check_wait_time_s'])
    do_drain_nodes = str_to_bool(CONFIG['misc']['do_drain_nodes'])
    
    states_to_check = parse_multiline_config_list(CONFIG['nodes']['states_to_check'])
    states_not_to_check = parse_multiline_config_list(CONFIG['nodes']['states_not_to_check'])
    partitions = CONFIG['nodes']['partitions_to_check']
    include_nodes = parse_multiline_config_list(CONFIG['nodes']['include_nodes'])
    exclude_nodes = parse_multiline_config_list(CONFIG['nodes']['exclude_nodes'])

    while True:
        for node in find_slurm_nodes(partitions, include_nodes):
            if not do_check_node(node, states_to_check, states_not_to_check,
                                 include_nodes, exclude_nodes):
                continue # next node
            # else:
            gpu_works, check_report = check_gpu(node)
            if gpu_works:
                LOG.info(f"{node} works")
                time.sleep(post_check_wait_time_s)
                continue # next node
            # else:
            LOG.error(f"{node} doesn't work!")
            if do_drain_nodes:
                drain_success, drain_report = drain_node(node, 'nvidia-smi failure')
            else:
                drain_success, drain_report = False, "drain disabled in config"
            if do_send_email:
                subject = f"gpu-checker has found an error on {node}"
                if not drain_success:
                    subject = subject + " and FAILED to drain the node"

                full_report = multiline_str(
                    "gpu check:",
                    indent(check_report),
                    '',
                    "drain operation:",
                    indent(drain_report)
                )
                send_email(
                    CONFIG['email']['to'],
                    CONFIG['email']['from'],
                    subject,
                    full_report
                )
            # each loop takes about 5 seconds on its own, most of the delay is the ssh command
            time.sleep(post_check_wait_time_s)
