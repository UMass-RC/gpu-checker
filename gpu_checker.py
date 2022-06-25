"""
Simon Leary
6/24/2022
GPU Checker
Loops with `sinfo` over nodes that are in both STATES_TO_CHECK and PARTITIONS_TO_CHECK
ssh's in using SSH_USER and SSH_PRIVKEY_FQN, tries to run `nvidia-smi`
If that fails in any way, send an email to EMAIL_TO from EMAIL_FROM (and put the node in DRAINING state)***
It actually sends two emails - one that there's an error and another that it's being put into DRAINING

CONFIG_FILE_PATH contains a cleartext password
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

CONFIG_FILE_PATH = '/opt/gpu-checker/secretfile.txt'
CONFIG = None

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

    nodes = [line.split(' ')[0] for line in remove_empty_lines(shell_output)]
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
    print(
        "sending email:_______________________________________________________________",
        f"to: {to}",
        f"from: {_from}",
        f"subject: {subject}",
        "body:",
        body,
        sep='\n'
    )
    msg = EmailMessage()
    msg.set_content(body)
    msg['To'] = to
    msg['From'] = _from
    msg['Subject'] = subject

    hostname = CONFIG['smtp_auth']['hostname']
    port = int(CONFIG['smtp_auth']['port'])
    user = CONFIG['smtp_auth']['user']
    password = CONFIG['smtp_auth']['password']
    is_ssl = str_to_bool(CONFIG['smtp_auth']['is_ssl'])

    if is_ssl:
        s = smtplib.SMTP_SSL(hostname, port, timeout=5)
    else:
        s = smtplib.SMTP(hostname, port, timeout=5)
    s.login(user, password)
    s.send_message(msg)
    s.quit()

    print("email sent successfully!____________________________________________________")

if __name__=="__main__":
    CONFIG = configparser.ConfigParser()
    if os.path.isfile(CONFIG_FILE_PATH):
        CONFIG.read(CONFIG_FILE_PATH)
    else:
        # write default empty config file
        CONFIG['nodes'] = {
            "states_to_check" : "mixed,idle",
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
            "signature" : ""
        }
        CONFIG['smtp_auth'] = {
            "hostname" : "",
            "port" : "",
            "user" : "",
            "password" : "",
            "is_ssl" : "False"
        }
        with open(CONFIG_FILE_PATH, 'w', encoding='utf-8') as config_file:
            CONFIG.write(config_file)

    states = CONFIG['nodes']['states_to_check']
    partitions = CONFIG['nodes']['partitions_to_check']
    do_send_email = str_to_bool(CONFIG['email']['enabled'])

    while True:
        for node in find_slurm_nodes(partitions):
            #print(node, do_check_node(node))
            if do_check_node(node):
                gpu_works, check_report = check_gpu(node)
                if gpu_works:
                    print(f"{node} works")
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
            # TODO uncomment me
            # each loop takes about 5 seconds on its own, most of the delay is the ssh command
                #time.sleep(60)
