"""
Simon Leary
6/23/2022
GPU Checker
Loops with `sinfo` over nodes that are in both STATES_TO_CHECK and PARTITIONS_TO_CHECK
ssh's in using SSH_USER and SSH_PRIVKEY_FQN, tries to run `nvidia-smi`
If that fails in any way, send an email to EMAIL_TO from EMAIL_FROM (and put the node in DRAINING state)***
It actually sends two emails - one that there's an error and another that it's being put into DRAINING

***Right now the command for draining is commented out, it will just send one email and take no action
I was asked to write a script to check for a particular error, but instead I wrote one to check for
anything that isn't return code 0, and that's why I haven't told it to automatically drain
If it turns out that the only thing it ever reports is the particular error, then maybe I will

TODO
remove this is a test prepend email body
remove draining from states search once email is working
decide whether or not to automatically drain nodes
re enable time sleep
"""
import subprocess
import time
import datetime
import smtplib
from email.message import EmailMessage

# For some reason, when you include 'allocated' to the states list,  sinfo shows you
# draining nodes. Which is frustrating.
# but, to ssh into a fully allocated node would mean using resources that are meant for already
# in use by a user, which I'd rather avoid. So, look for states that have
# at least one idle core -> either mixed (mixed allocated and idle) or fully idle
#STATES_TO_CHECK = "mixed,idle"
STATES_TO_CHECK = "mixed,idle,draining"
PARTITIONS_TO_CHECK = "ials-gpu"

SSH_USER = 'root'
SSH_PRIVKEY_FQN = '/root/.ssh/unity_root_privkey_rsa'

EMAIL_TO = 'hpc@it.umass.edu'
EMAIL_FROM = 'hpc@it.umass.edu'
EMAIL_PREPEND_STRING = "THIS IS A TEST\n"

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

def purge_element(_list: list, elem_to_purge) -> list:
    return list(filter(lambda elem: elem != elem_to_purge, _list))

class ShellRunner:
    """
    spawn this with a shell command, then you have access to stdout, stderr, exit code,
    along with a boolean of whether or not the command was a success
    and if you use str(your_shell_runner), you get a formatted report of all the above
    """
    def __init__(self, command):
        # these should all get defined by self.run_shell_command
        self.last_shell_output = ''
        self.shell_error = ''
        self.exit_code = -1
        self.command_report = ''
        self.success = None

        self.run_shell_command(command)

    def __str__(self):
        return self.command_report

    def run_shell_command(self, command) -> None:
        """
        runs the command, defines the variables, quits
        this uses check=True for subprocess, but it catches the subprocess.CalledProcessError
        and simply puts it in the command_report
        """
        try:
            process = subprocess.run(
                command,
                capture_output=True,
                check=True,
                shell=True
            )
            # process.std* returns a bytes object, convert to string
            self.shell_output = str(process.stdout, 'UTF-8')
            self.shell_error = str(process.stderr, 'UTF-8')
            self.exit_code = process.returncode
            self.success = self.exit_code == 0
            self.command_report = multiline_str(
                "command success:",
                self.success,
                '',
                "command:",
                command,
                '',
                "stdout:",
                self.shell_output,
                '',
                "stderr:",
                self.shell_error,
                '',
                "exit code:",
                self.exit_code
            )

        except subprocess.CalledProcessError as exc:
            self.success = False
            self.command_report = multiline_str(
                "command:",
                command,
                '',
                "python exception:",
                str(exc)
            )

def find_slurm_nodes(states: str, partitions: str) -> None:
    """"
    return a list of node names that meet the specified states and partitions
    states and partitions are comma delimited strings
    """
    command_results = ShellRunner(f"sinfo --states={states} --partition={partitions} -N --noheader")
    success = command_results.success
    shell_output = command_results.shell_output
    command_report = str(command_results)

    if not success:
        raise Exception(command_report) # barf

    shell_output_lines = [line.replace('\n', '') for line in shell_output.split('\n')]
    shell_output_lines = purge_element(shell_output_lines, '')
    nodes = [line.split(' ')[0] for line in shell_output_lines]
    return nodes

def drain_node(node: str, do_send_email=True):
    """"
    tell slurm to put specified node into DRAINING state
    """
    command_results = ShellRunner(f"scontrol update nodename={node} state=draining")
    success = command_results.success
    command_report = str(command_results)

    if do_send_email:
        if success:
            send_email(
                EMAIL_TO,
                EMAIL_FROM,
                f"gpu-checker has drained node {node}",
                command_report
            )
        else:
            send_email(
                EMAIL_TO,
                EMAIL_FROM,
                f"ACTION REQUIRED: gpu-checker wanted to drain node {node}, but failed",
                command_report
            )

def check_gpu(node: str, do_send_email=True) -> bool:
    """
    check `nvidia-smi`
    returns True if it works, false if it doesn't
    """
    #command = f"ssh simon@{node} -o \"StrictHostKeyChecking=no\" -p 22000 -i {SSH_PRIVKEY_FQN} nvidia-smi || echo $?"
    command = f"ssh {SSH_USER}@{node} -o \"StrictHostKeyChecking=no\" -i {SSH_PRIVKEY_FQN} nvidia-smi && echo $? || echo $?"
    command_results = ShellRunner(command)
    shell_output = command_results.shell_output
    command_report = str(command_results)

    # find exit code that was put into stdout when I said `|| echo $?`
    shell_output_lines = [line.replace('\n', '') for line in shell_output.split('\n')]
    shell_output_lines = purge_element(shell_output_lines, '')
    ssh_exit_code = shell_output_lines[-1]

    success = command_results.success and int(ssh_exit_code) == 0

    if not success and do_send_email:
        send_email(
            EMAIL_TO,
            EMAIL_FROM,
            f"gpu-checker has detected an error on node {node}",
            command_report
        )

    if success:
        print(f"gpu works on node {node}")
    return success

def send_email(to: str, _from: str, subject: str, body: str):
    """
    send an email using an SMTP server on localhost
    """
    body = EMAIL_PREPEND_STRING + body
    print(
        f"{datetime.datetime.now()} sending email:_____________________________________",
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

    s = smtplib.SMTP('mailhub.oit.umass.edu', 465)
    s.login('hpc', 'passwd')
    s.send_message(msg)
    s.quit()

    print("email sent successfully!____________________________________________________")

if __name__=="__main__":
    while True:
        for node in find_slurm_nodes(STATES_TO_CHECK, PARTITIONS_TO_CHECK):
            gpu_works = check_gpu(node)
            if not gpu_works:
                # TODO uncomment this?
                #drain_node(node)
                pass
            # each loop takes about 5 seconds on its own, don't know why
            # TODO uncomment me
            #time.sleep(60)
