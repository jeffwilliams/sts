# STS -- SSH Tunnel Service

STS starts ssh tunnels.

# Usage

First create a configuration file at `/etc/sts/config.yaml`, `$HOME/.sts/config.yaml`, or in the current directory as `.sts/config.yaml`. The contents should be as the following example:

    # SSH username
    user: mranderson
    # SSH destination
    dest: yourserver:22
    # Path to your password-protected, PEM encoded private key:
    key: /path/to/id_rsa
    # In tunnels, define a list of tunnels to open
    tunnels:
      - 
        local: ":8020"
        remote: "localhost:80" 

Then run sts.
