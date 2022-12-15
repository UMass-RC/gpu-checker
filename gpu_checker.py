#!/usr/bin/env python3
CONFIG_PREPEND = """
# CONFIG_FILE_NAME contains a cleartext password
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
import logging
from logging.handlers import RotatingFileHandler
import sys
import traceback
import paramiko as pm

CONFIG_FILE_NAME="gpu_checker_config.ini"
LOG = None # init_logger()
SLURM_GPU_COUNTS = dict() # init_gpu_counts()

class SshError(Exception):
    pass

def multiline_str(*argv: str) -> str:
    """
    a string with one line per argument
    """
    return os.linesep.join(argv)

def indent(string: str, indenter="    ", num_indents=1) -> str:
    """
    add the indenter (default four spaces) to the beginning of each line in the string
    """
    for i in range(num_indents):
        string = indenter + string # first line
        string = string.replace(os.linesep, os.linesep+indenter) # all other lines
    return string

def remove_empty_lines(string: str) -> str:
    return os.linesep.join([line for line in string.splitlines() if line])

def count_lines(string: str) -> int:
    return string.count(os.linesep)+1

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

class _SSHClient(pm.SSHClient):
    """
    same as paramiko.SSHClient but it includes a wrapper function _exec_command
    """
    def _exec_command(self, *argv, encoding="UTF-8") -> Tuple[int, str, str]:
        """
        same as exec_command but instead of stdin it returns exit status
        and stdout/stderr are strings
        """
        stdin, stdout, stderr = self.exec_command(*argv)
        exit_status = stdout.channel.recv_exit_status()
        stdout = remove_empty_lines(str(stdout.read(), encoding))
        stderr = remove_empty_lines(str(stderr.read(), encoding))
        return exit_status, stdout,stderr

class ShellRunner:
    """
    spawn this with a shell command, then you have access to stdout, stderr, exit code,
    along with a boolean of whether or not the command was a success (exit code 0)
    and if you use str(your_shell_runner), you get a formatted report of all the above
    """
    def __init__(self, command, timeout_s):
        try:
            process = subprocess.run(
                command,
                capture_output=True,
                shell=True,
                timeout=timeout_s
            )
            # process.std* returns a bytes object, convert to string
            self.shell_output = remove_empty_lines(str(process.stdout, 'UTF-8'))
            self.shell_error = remove_empty_lines(str(process.stderr, 'UTF-8'))
            self.exit_code = process.returncode
        except subprocess.TimeoutExpired as timeout_err:
            try:
                self.shell_output = remove_empty_lines(str(timeout_err.stdout, 'UTF-8'))
            except TypeError:
                self.shell_output = ''
            try:
                self.shell_error = remove_empty_lines(str(timeout_err.stderr, 'UTF-8'))
            except TypeError:
                self.shell_error = f'timeout after {timeout_s} seconds!'
            self.exit_code = 1

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

def find_slurm_nodes(partitions='', include_nodes=[]) -> None:
    """"
    return a list of node names that are in the specified partitions
    partitions is a slurm formatted list (comma separated with extra options)
    partitions can be an empty string, it'll just list the include_nodes
    """
    nodes = include_nodes
    if partitions.strip() != '':
        command = f"sinfo --partition={partitions} -N --noheader -o '%N' | sort -u"
        command_results = ShellRunner(command, 10)
        success = command_results.success
        shell_output = command_results.shell_output
        command_report = str(command_results)
        if not success:
            raise Exception(command_report) # barf

        nodes = shell_output.splitlines()

        if shell_output.replace('\n','').strip() == '':
            LOG.error(command_report)

        for exclude_node in exclude_nodes:
            nodes = purge_element(nodes, exclude_node)
        # check for nodes that barely missed exclusion due to capitalization
        for exclude_node in exclude_nodes:
            for node in nodes:
                # is a strip() necessary?
                if node.lower().strip() == exclude_node.lower().strip():
                    LOG.warning(f"included node '{node}' is similar to exclusion '{exclude_node}'")

    if len(nodes) == 0:
        raise Exception(multiline_str(
            "found 0 nodes!",
            f"partition_list: {partitions}",
            f"include_nodes: {include_nodes}"
        ))
    return nodes

def do_check_node(node: str, states_to_check: list, states_not_to_check: list,
                  include_nodes=[], exclude_nodes=[], do_log=True) -> bool:
    """
    do I want to check this node?
    read the readme
    """
    do_check = False
    reasons = []
    command_results = ShellRunner(f"scontrol show node {node}", 10)
    command_output = command_results.shell_output
    if re.match(r"Node (\S+) not found", command_output):
        LOG.error(command_output)
        return False
    # is the node listed in include nodes? If yes, skip all other checks
    do_skip_node_state_logic = False
    for include_node in include_nodes:
        if node.lower() == include_node.lower():
            do_check = True
            reasons = ["listed in include_nodes"]
            do_skip_node_state_logic = True
    if not do_skip_node_state_logic:
        # scontrol has states delimited by '+'
        states = re.search(r"State=(\S*)", command_output).group(1).split('+')
        do_break = False
        for state in states:
            # is the node listed in states to check? If yes, do_check=True and return
            for good_state in states_to_check:
                if state.lower() == good_state.lower():
                    do_check = True
                    reasons.append(good_state)
            # is the node listed in states not to check? If yes, do_check=False and return
            for bad_state in states_not_to_check:
                if state.lower() == bad_state.lower():
                    do_check = False
                    reasons = [bad_state] # overwrite other reasons
                    do_break = True # nested break
                    break
            if do_break: # nested break
                break
    if do_log:
        if len(reasons) == 0:
            reasons = ["no relevant states"]
        LOG.info(f"checking node {node}?\t{do_check} because {','.join(reasons)}")
    return do_check

def drain_node(node: str, reason: str) -> Tuple[bool, str]:
    """"
    tell slurm to put specified node into DRAINING state
    returns True if it works, false if it doesn't
    also returns formatted report of the operation
    """
    command_results = ShellRunner(f"scontrol update nodename={node} state=drain reason=\"{reason}\"", 10)
    success = command_results.success
    command_report = str(command_results)
    return success, command_report

def check_gpu(node: str, ssh_user: str, key_filename: str, timeout_s=0) -> Tuple[bool, str, str]:
    """
    checks that nvidia-smi works, works in a reasonable amount of time,
    and reports the same number of GPUs that are listed in SLURM_GPU_COUNTS global dict

    0 timeout means never timeout

    returns:
    - boolean of whether the check passed or not
    - short (couple words) summary of what happened
    - complete report of what happened
    """
    command = "nvidia-smi -L"
    if timeout_s > 0:
        command = f"timeout -v {timeout_s} " + command
    ssh_client = _SSHClient()
    ssh_client.set_missing_host_key_policy(pm.MissingHostKeyPolicy()) # do nothing
    try:
        ssh_client.connect(node, username=ssh_user, key_filename=key_filename)
    except Exception:
        full_report = traceback.format_exc()
        short_summary = "SSH failed to connect"
        passed = False
        return passed, short_summary, full_report
    exit_code, stdout, stderr = ssh_client._exec_command(command)
    ssh_client.close()
    full_report = multiline_str(
        f"command: {command}",
        f"exit code: {exit_code}",
        "stdout:",
        indent(stdout),
        '',
        "stderr:",
        indent(stderr),
    )
    short_summary = f"nvidia-smi exit code {exit_code}"
    passed = (exit_code == 0)

    num_gpus_found = count_lines(stdout)
    num_gpus_expected = SLURM_GPU_COUNTS[node]
    if passed & (num_gpus_found != num_gpus_expected):
        num_gpus_report = multiline_str(
            f"number of GPUs counted: {num_gpus_found}",
            f"nummber of GPUs expected based on slurm.conf: {num_gpus_expected}"
        )
        short_summary = "wrong number of GPUs"
        full_report = full_report + '\n' + num_gpus_report
        passed = False
    if "Unable to determine the device handle for gpu" in stdout:
        short_summary = "nvidia-smi device handle error"
    if "timeout" in stderr:
        short_summary = "nvidia-smi timeout"

    return passed, short_summary, full_report

def send_email(to: str, _from: str, subject: str, body: str, signature: str,
               hostname: str, port: int, user: str, password: str, is_ssl: bool) -> None:
    body = multiline_str(
        body,
        '',
        signature
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

    if is_ssl:
        smtp = smtplib.SMTP_SSL(hostname, port, timeout=5)
    else:
        smtp = smtplib.SMTP(hostname, port, timeout=5)
    smtp.login(user, password)
    smtp.send_message(msg)
    smtp.quit()

    LOG.info("email sent successfully!____________________________________________________")

def init_logger(info_filename='gpu_checker.log', error_filename='gpu_checker_error.log',
                max_filesize_megabytes=100, backup_count=1, do_print=True,
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
        maxBytes=max_filesize_megabytes*1024*1024,
        backupCount=backup_count)
    file_handler_info.setFormatter(log_formatter)
    file_handler_info.setLevel(logging.INFO)
    log.addHandler(file_handler_info)

    file_handler_error = RotatingFileHandler(
        error_filename,
        mode='w',
        maxBytes=max_filesize_megabytes*1024*1024,
        backupCount=backup_count)
    file_handler_error.setFormatter(log_formatter)
    file_handler_error.setLevel(logging.ERROR)
    log.addHandler(file_handler_error)

    log.setLevel(logging.INFO)

    # global exception handler write to log file
    def my_excepthook(exc_type, exc_value, exc_traceback):
        exc_lines = traceback.format_exception(exc_type, "", exc_traceback)
        exc_lines = [line.strip() for line in exc_lines]
        for line in exc_lines:
            LOG.error(line)
        LOG.error(exc_value)
        sys.exit(-1)
    sys.excepthook = my_excepthook

    return log

def init_gpu_counts():
    global SLURM_GPU_COUNTS
    command = r"sinfo --noheader -N  -o '%N|%G' | sort -u"
    command_results = ShellRunner(command, 10)
    command_report = str(command_results)
    if not command_results.success:
        raise Exception(command_report) # barf
    for line in command_results.shell_output.splitlines():
        node, gres_str = line.split('|')
        if gres_str=="(null)":
            SLURM_GPU_COUNTS[node] = 0
            continue
        # example gres_str:
        # "gpu:tesla:2,gpu:kepler:2,mps:400,bandwidth:lustre:no_consume:4G"
        num_gpus = 0
        for gres in gres_str.split(','):
            gres_type,gres_data_str = gres.split(':',1)
            if gres_type == "gpu":
                num_gpus += int(gres_data_str.split(':')[-1])
        SLURM_GPU_COUNTS[node] = num_gpus

def init_config():
    config = configparser.ConfigParser()
    if os.path.isfile(CONFIG_FILE_NAME):
        config.read(CONFIG_FILE_NAME)
    else:
        print(f"config file not found. Creating new one at {CONFIG_FILE_NAME}")
        config['nodes'] = {
            "states_to_check" : "allocated,mixed,idle",
            "states_not_to_check" : "drain",
            "partitions_to_check" : "gpu",
            "include_nodes" : "",
            "exclude_nodes" : ""
        }
        config['ssh'] = {
            "user" : "root",
            "keyfilename" : "/root/.ssh/id_rsa"
        }
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
        config['logger'] = {
            "info_filename" : "gpu_checker.log",
            "error_filename" : "gpu_checker_error.log",
            "max_filesize_megabytes" : "100",
            "backup_count" : "1"
        }
        config['misc'] = {
            "post_check_wait_time_s" : "60",
            "do_drain_nodes" : "False",
            "check_timeout_s" : "30",
        }
        with open(CONFIG_FILE_NAME, 'w', encoding='utf-8') as config_file:
            config_file.write(CONFIG_PREPEND)
            config.write(config_file)
        os.chmod(CONFIG_FILE_NAME, 0o600) # 0o means octal digits
        raise SystemExit()
    return config

if __name__=="__main__":
    config = init_config()

    info_filename = config['logger']['info_filename']
    error_filename = config['logger']['error_filename']
    max_filesize_megabytes = int(config['logger']['max_filesize_megabytes'])
    backup_count = int(config['logger']['backup_count'])
    LOG = init_logger(info_filename, error_filename, max_filesize_megabytes, backup_count)
    LOG.info("hello, world!")

    do_send_email = str_to_bool(config['email']['enabled'])
    post_check_wait_time_s = int(config['misc']['post_check_wait_time_s'])
    do_drain_nodes = str_to_bool(config['misc']['do_drain_nodes'])
    check_timeout_s = int(config['misc']['check_timeout_s'])

    states_to_check = parse_multiline_config_list(config['nodes']['states_to_check'])
    states_not_to_check = parse_multiline_config_list(config['nodes']['states_not_to_check'])
    # TODO the other lists use parse_multiline... but this doesnt. why?
    partitions = config['nodes']['partitions_to_check']
    include_nodes = parse_multiline_config_list(config['nodes']['include_nodes'])
    exclude_nodes = parse_multiline_config_list(config['nodes']['exclude_nodes'])

    ssh_user = config['ssh']['user']
    ssh_keyfilename = config['ssh']['keyfilename']

    init_gpu_counts()

    for node in find_slurm_nodes(partitions, include_nodes):
        if not do_check_node(node, states_to_check, states_not_to_check,
                                include_nodes, exclude_nodes):
            continue
        try:
            gpu_works, drain_message, check_report = check_gpu(node, ssh_user, ssh_keyfilename, timeout_s=check_timeout_s)
        except SshError as e:
            LOG.error(f"unable to check node {node}")
            LOG.error(str(e))
            time.sleep(post_check_wait_time_s)
            continue
        if gpu_works:
            LOG.info(f"{node} works")
            time.sleep(post_check_wait_time_s)
            continue
        # else:
        LOG.error(f"{node} doesn't work!")
        if do_drain_nodes:
            drain_success, drain_report = drain_node(node, drain_message)
        else:
            drain_success, drain_report = False, "drain disabled in config"
        if do_send_email:
            subject = f"{node} {drain_message} (gpu-checker)"
            if not drain_success:
                subject = subject + " (not drained)"

            full_report = multiline_str(
                "gpu check:",
                indent(check_report),
                '',
                "drain operation:",
                indent(drain_report)
            )
            send_email(
                config['email']['to'],
                config['email']['from'],
                subject,
                full_report,
                config['email']['signature'],
                config['email']['smtp_server'],
                int(config['email']['smtp_port']),
                config['email']['smtp_user'],
                config['email']['smtp_password'],
                str_to_bool(config['email']['smtp_is_ssl'])
            )
        # each loop takes about 5 seconds on its own, most of the delay is the ssh command
        LOG.info(f"sleeping {post_check_wait_time_s} seconds...")
        time.sleep(post_check_wait_time_s)
