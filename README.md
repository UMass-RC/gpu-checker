# unity-gpu-checker
* Loops over nodes that are included in the config
* ssh's in and tries to run `nvidia-smi`
* If that fails , drain the node and send an email
* script should be run as root

# how it picks nodes

the following are all config options:

* partitions to check - the list of nodes from which the other logic decides whether or not to check each node
  ```
  sinfo --partition={partitions_to_check} -N --noheader
  ```
* include nodes - gets added to the list and do_check = True
* exclude nodes - gets removed from the list
* states to check - if any of these are found, do_check = True
* states not to check - if any of these are found, do_check = False, overwrites all else

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
max_filesize_mb = 1024
backup_count = 1

[misc]
post_check_wait_time_s = 60

```
