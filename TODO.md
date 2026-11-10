# TODO

- [x] add internal ip column in `dev-vps list` command. also output in `dev-vps create`.

- [x] pipe startup script error/output to /dev-vps/startup.log in VPS

- [x] BUG: command `dev-vps ssh` after ctrl+d from server. it show usage help text

- [x] add command to copy dev-vps ssh keys to given path. (default to current dir)

- [x] add command to import exist user ssh keys from `~/.ssh` to `~/.dev-vps/.ssh`

- [x] make `dev-vps list` fetch from api. to prevent stale info from other user machine.
