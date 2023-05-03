#!/usr/bin/env python3

import subprocess
import time
from typing import Tuple
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

def multiline_str(*argv: str) -> str:
    """
    a string with one line per argument
    """
    return os.linesep.join(argv)

class ShellCommandError(Exception):
    pass

def shell_command(command: str, timeout_s: int, shell="/bin/bash") -> Tuple[str, str]:
    command = "set -e; set -o pipefail; " + command
    try:
        process = subprocess.run(command, timeout=timeout_s, capture_output=True,
                                shell=True, check=True, executable=shell, encoding="UTF-8")
        report = multiline_str(
                "command:",
                indent(command),
                f"return code: {process.returncode}",
                "stdout:",
                indent(process.stdout),
                "stderr:",
                indent(process.stderr)
            )
        return process.stdout.strip(), report
    except subprocess.CalledProcessError as err:
        fail_report = multiline_str(
                "command:",
                indent(command),
                f"return code: {err.returncode}",
                "stdout:",
                indent(err.stdout),
                "stderr:",
                indent(err.stderr)
            )
        raise ShellCommandError(fail_report) from err

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

def parse_multiline_config_list(string: str, do_lowercase=False) -> list:
    """
    delete newlines, split by commas, strip each string, remove empty strings
    """
    if do_lowercase:
        string = string.lower()
    return purge_element([state.strip() for state in string.replace('\n', '').split(',')], '')

def str_to_bool(string: str) -> bool:
    if string.lower() in ['true', '1', 't', 'y', 'yes']:
        return True
    if string.lower() in ['false', '0', 'f', 'n', 'no']:
        return False
    raise RuntimeError(f"Can't convert {string} to boolean")

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

def find_slurm_nodes(partitions='', include_nodes=[], exclude_nodes=[]) -> None:
    """"
    return a list of node names that are in the specified partitions
    partitions is a slurm formatted list (comma separated with extra options)
    partitions can be an empty string, it'll just list the include_nodes
    """
    nodes = include_nodes
    if len(partitions) != 0:
        command = f"sinfo --partition={partitions} -N --noheader -o '%N' | sort -u"
        stdout, command_report = shell_command(command, 10)
        if stdout == "":
            raise RuntimeError('\n'.join(["empty output from `sinfo`!", command_report]))
        nodes = nodes + [x.lower().strip() for x in stdout.splitlines()]
        nodes = purge_element(nodes, "")
        for exclude_node in exclude_nodes:
            nodes = purge_element(nodes, exclude_node)
    if len(nodes) == 0:
        raise RuntimeError(multiline_str(
            "found 0 nodes!",
            f"partitions: {partitions}",
            f"include_nodes: {include_nodes}"
        ))
    return nodes

def do_check_node(node: str, states_to_check: list, states_not_to_check: list,
                  include_nodes=[], do_log=True) -> bool:
    """
    do I want to check this node?
    read the readme
    """
    if node in include_nodes:
        LOG.info(f"checking node {node}?\t{True} because it's listed in include_nodes[]")
        return True
    do_check = False
    reasons = []
    try:
        stdout, command_report = shell_command(f"scontrol show node {node}", 10)
    except subprocess.CalledProcessError as err:
        LOG.error(str(err))
        return False
    # scontrol has states delimited by '+'
    states = re.search(r"State=(\S*)", stdout).group(1).lower().split('+')
    for state in states:
        # is the node listed in states to check? If yes, do_check=True and return
        if state in states_to_check:
            reasons.append(state)
            do_check = True
        if state in states_not_to_check:
            reasons = [state] # overwrite other reasons
            do_check = False
            break
    if len(reasons) == 0:
        reasons = ["no relevant states"]
    if do_log:
        LOG.info(f"checking node {node}?\t{do_check} because {','.join(reasons)}")
    return do_check

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
    except (pm.SSHException, pm.AuthenticationException, pm.ChannelException):
        full_report = traceback.format_exc()
        short_summary = "SSH failed to connect"
        #passed = False
	    # Let slurm decide when a node is down
        passed = True
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
    short_summary = f"nvidia-smi returned {exit_code}"
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

def send_email(recipient: str, _from: str, subject: str, body: str, signature: str) -> None:
    LOG.info(multiline_str(
        "sending email:_______________________________________________________________",
        f"to: {recipient}",
        f"from: {_from}",
        f"subject: {subject}",
        "body:",
        body,
        "",
        signature
    ))
    body = body.replace('\n', "\\n")
    signature = signature.replace('\n', "\\n")
    cmd = f"echo -e \"From: {_from}\\nSubject :{subject}\\n\\n{body}\\n{signature}\" | /usr/sbin/sendmail -f {_from} {recipient}"
    shell_command(cmd, 30)
    LOG.info("email sent!")

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
        stdout_handler = logging.StreamHandler(sys.stdout)
        log.addHandler(stdout_handler)

        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setLevel(logging.ERROR)
        log.addHandler(stderr_handler)

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
        traceback_lines = [line.strip() for line in traceback.format_tb(exc_traceback)]
        LOG.error(f"exception type: {exc_type.__name__}")
        for line in traceback_lines:
            LOG.error(line)
        LOG.error(f"exception value: {exc_value}")
        sys.exit(1)
    sys.excepthook = my_excepthook

    return log

def init_gpu_counts():
    global SLURM_GPU_COUNTS
    command = r"sinfo --noheader -N  -o '%N|%G' | sort -u"
    stdout, command_report = shell_command(command, 10)
    for line in stdout.splitlines():
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
            "signature" : ""
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
    LOG = init_logger(info_filename.strip(), error_filename.strip(), max_filesize_megabytes, backup_count)
    LOG.info("hello, world!")

    do_send_email = str_to_bool(config['email']['enabled'])
    post_check_wait_time_s = int(config['misc']['post_check_wait_time_s'])
    do_drain_nodes = str_to_bool(config['misc']['do_drain_nodes'])
    check_timeout_s = int(config['misc']['check_timeout_s'])

    # parse multiline_config_list strips the strings and purges empty strings
    states_to_check = parse_multiline_config_list(config['nodes']['states_to_check'], do_lowercase=True)
    states_not_to_check = parse_multiline_config_list(config['nodes']['states_not_to_check'], do_lowercase=True)
    # don't use parse_multiline_config_list because this is supposed to be a string data type not list
    partitions = config['nodes']['partitions_to_check'].strip()
    include_nodes = parse_multiline_config_list(config['nodes']['include_nodes'], do_lowercase=True)
    exclude_nodes = parse_multiline_config_list(config['nodes']['exclude_nodes'], do_lowercase=True)
    ssh_user = config['ssh']['user'].strip()
    ssh_keyfilename = config['ssh']['keyfilename'].strip()

    init_gpu_counts()
    for node in find_slurm_nodes(partitions, include_nodes, exclude_nodes):
        if not do_check_node(node, states_to_check, states_not_to_check, include_nodes):
            continue
        gpu_works, drain_message, check_report = check_gpu(node, ssh_user, ssh_keyfilename, timeout_s=check_timeout_s)
        if gpu_works:
            LOG.info(f"{node} works")
            time.sleep(post_check_wait_time_s)
            continue
        LOG.error(f"{node} doesn't work!")
        if do_drain_nodes:
            try:
                cmd = f"scontrol update nodename={node} state=drain reason=\"{drain_message}\""
                stdout, drain_report = shell_command(cmd, 10)
                drain_success = True
            except subprocess.CalledProcessError as err:
                drain_report = str(err)
                drain_success = False
        else:
            drain_success = False
            drain_report = "drain disabled in config"
        if do_send_email:
            if drain_success:
                subject = f"{node} drained: {drain_message} (gpu-checker)"
            else:
                subject = f"{node} could be drained: {drain_message} (gpu-checker)"
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
            )
        # each loop takes about 5 seconds on its own, most of the delay is the ssh command
        LOG.info(f"sleeping {post_check_wait_time_s} seconds...")
        time.sleep(post_check_wait_time_s)
