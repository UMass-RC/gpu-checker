# unity-gpu-checker
* Loops over nodes that are included in the config
* ssh's in and tries to run `nvidia-smi`
* If that fails , drain the node and send an email
* script should be run as root

# node filtering pseudocode
```
nodes = ShellRunner(f"sinfo --partition={partitions_to_check} -N --noheader").command_output.splitlines()
nodes = [node.strip().split(' ')[0] for node in nodes] # first word before space
nodes = nodes + include_nodes

for node in nodes:
    if do_check_node(node):
        check_node(node)

def do_check_node(node):
    do_check = False
    
    if node in include_nodes : 
        do_check = True
    if node in exclude_nodes :
        return False

    states = find_states(node)
    for state in states:
        if state in states_to_check:
            do_check = True
        if state in states_not_to_check:
            return False
    return do_check
```

# logging
logfile names in config can be absolute or relative to cwd

creates up to 4 log files, each up to size max_filesize_megabytes
  * info_filename
  * info_filename.1 (rollover)
  * error_filename
  * error_filename.1 (rollover)

info_filename contains all logs, including errors

# sample config file:
gpu_checker_config.ini will be created (.gitignore and chmod 700) in cwd when the script is run for the first time
* this file contains a cleartext password
  * should be excluded from source control!
  * should not be readable by any other user!

partitions_to_check is pasted directly into slurm CLI, no multiline

```
[nodes]
states_to_check = 
  allocated,
  mixed,
  idle
states_not_to_check = 
  drain
partitions_to_check = gpu,alsogpu
include_nodes = 
  gpu10,
  gpu68
exclude_nodes =
  gpu8,
  gpu3

[ssh]
user = root
keyfile = /root/.ssh/id_rsa

[email]
enabled = True
to = hpc@it.umass.edu
from = hpc@it.umass.edu
signature = best, gpu_checker
smtp_server = mailhub.oit.umass.edu
smtp_port = 465
smtp_user = admin
smtp_password = password
smtp_is_ssl = True

[logger]
info_filename = gpu_checker.log
error_filename = gpu_checker_error.log
max_filesize_megabytes = 1024
backup_count = 1

[misc]
post_check_wait_time_s = 60
do_drain_nodes = True

```
