# TODO

- [x] add internal ip column in `dev-vps list` command. also output in `dev-vps create`.

- [x] pipe startup script error/output to /dev-vps/startup.log in VPS

- [x] BUG: command `dev-vps ssh` after ctrl+d from server. it show usage help text

- [x] add command to copy dev-vps ssh keys to given path. (default to current dir)

- [x] add command to import exist user ssh keys from `~/.ssh` to `~/.dev-vps/.ssh`

- [x] make `dev-vps list` fetch from api. to prevent stale info from other user machines.

- [x] add firewall for droplets. 
    - create firewall for each droplet. 
    - destroy firewall when droplet destroy. 
    - default ports: 22 (always), 80, 443, 8080, 8081, 3000, 8000.

- [x] add command to allow ports for a droplet. `dev-vps firewall allow <droplet_name> <port_list>`. example `dev-vps firewall allow my-droplet 9000 9001 9002`

- [x] add command to deny ports for a droplet. `dev-vps firewall deny <droplet_name> <port_list>`. example `dev-vps firewall deny my-droplet 9000 9001 9002`

- [x] add command to list firewall rules for a droplet. `dev-vps firewall list <droplet_name>`

- [x] add input for custom droplet size at "Select Server Size" list.
