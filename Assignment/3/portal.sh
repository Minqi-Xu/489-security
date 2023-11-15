#!/bin/bash -e

# Welcome to The Assignment Portal of CS 489/698 - Software and Systems Security
#
# This is not a regular website for broadcasting information. Instead, it is a
# web service hidden behind the HTTP protocol and only intended for users of the
# Software and Systems Security course for assignment-related tasks.
#
# The file you are currently viewing is a Bash-based client to interact with
# the web service. This script is designed for a UNIX-like system (e.g., Ubuntu,
# MacOS, or WSL on Windows) with `bash`, `curl`, and `ssh-keygen` available.
#
# To use this file,
# - save it as a script (e.g., `portal.sh`)
# - change its permission if needed (e.g., `chmod +x portal.sh`) and
# - check its help message `./portal.sh help`

# course variables (SET BY USERS)
USR_DEFAULT=m259xu
KEY_DEFAULT=key

# course variables (SET BY ADMIN)
GATEWAY=ugster71a.student.cs.uwaterloo.ca:8000
NAMESPACE=s3

# alternative to set user info: environment variable
if [ -z "${U}" ]; then
  USR="${USR_DEFAULT}"
else
  USR="${U}"
fi

if [ -z "${K}" ]; then
  KEY="${KEY_DEFAULT}"
else
  KEY="${K}"
fi

# command: print help message
function cmd_help() {
  cat <<EOF
This is a Bash-based Client to the Assignment Portal of CS 489/698

Before using this script, please check that you have set the course variables
correctly on top of this file, including:
- USR_DEFAULT, your UWaterloo username (currently set to "${USR_DEFAULT}")
- KEY_DEFAULT, a path prefix for your key files (currently set to "${KEY_DEFAULT}")

Alternatively, you can supply the same information via environment variables
before calling this script, e.g.,
U=<username> K=<path-prefix-to-passkey> ./portal.sh <command>

Your current username is "${USR}" and path-prefix to passkey is "${KEY}".

The following commands are available for everyone for VM management
- help: print this help message
- register: create a ed25519 key pair and register the user with the public key
- status: check the status of the virtual machine allocated to the user
- launch: launch the virtual machine allocated to the user
- destroy: destroy the virtual machine allocated to the user
- ssh: SSH into the virtual machine allocated to the user

The following commands are available for everyone for building the passkey server
- peek <uid>: examine up to 64 registration and login records from <uid>'s server
- attack <uid>: launch the MiTM attack using your own script against <uid>'s server
- proxy_register <test[1-5]>: register a new user <testN> on your own passkey server
- proxy_login <test[1-5]>: login as a new user <testN> on your own passkey server

The following command are available if you are a system administrator
- reset <uid>: reset the user to a state before registration
- snapshot: take a snapshot of all VMs in the system
- populate: reload the snapshot of all VMs in the system
- shutdown: send a shutdown request to the system
EOF
}

# command (special): generate a key pair and register a user with the public key
function cmd_special_register() {
  ssh-keygen -t ed25519 -C "${USR}@${NAMESPACE}" -f "${KEY}" -P ""
  curl -s "${GATEWAY}/${USR}/register" -d @"${KEY}.pub"
  echo ""
  echo "!!! IMPORTANT !!!"
  echo "- Please keep your private key in a safe place."
  echo "- If you lose it, you will LOSE ACCESS TO THE SYSTEM FOREVER."
}

# command (special): ssh into the allocated VM
function cmd_special_ssh() {
  local C=$(cmd_generic "config")
  local X=(${C//:/ })
  ssh -i ${KEY} vagrant@${X[0]} -p ${X[1]}
}

# command (special): bridge into another users' recent proxy requests
function cmd_special_bridge() {
  if [ -z "$2" ]; then
    TARGET="${USR}"
  else
    TARGET="$2"
  fi
  local T=$(date +%s)
  local S=$(echo -n "${T}" | ssh-keygen -Y sign -f "${KEY}" -n "${NAMESPACE}" -)
  curl -s -X POST "${GATEWAY}/${USR}/$1/${TARGET}" -d "${S}"
}

# command (generic): run a generic query
function cmd_generic() {
  local T=$(date +%s)
  local S=$(echo -n "${T}" | ssh-keygen -Y sign -f "${KEY}" -n "${NAMESPACE}" -)
  curl -s -X POST "${GATEWAY}/${USR}/$1" -d "${S}"
}

# command (generic): run a generic query (for admin commands)
function cmd_generic_admin() {
  local T=$(date +%s)
  local S=$(echo -n "${T}" | ssh-keygen -Y sign -f "${KEY}" -n "${NAMESPACE}" -)
  curl -s -X POST "${GATEWAY}/${USR}/$1/$2" -d "${S}"
}

# command (proxy): generate a key pair and register a user with the public key
function cmd_proxy_special_register() {
  ssh-keygen -t ed25519 -C "${USR}@${NAMESPACE}" -f "${KEY}_$1" -P ""
  local D=$(cat "${KEY}_$1.pub")
  local T=$(date +%s)
  local S=$(echo -n "${T}" | ssh-keygen -Y sign -f "${KEY}" -n "${NAMESPACE}" -)
  curl -s -X POST "${GATEWAY}/${USR}/proxy/register/$1" -H "DATA: ${D}" -d "${S}"
}

# command (proxy): run a generic query via proxy
function cmd_proxy_generic() {
  local T=$(date +%s)
  local S=$(echo -n "${T}" | ssh-keygen -Y sign -f "${KEY}" -n "${NAMESPACE}" -)
  local D=$(echo -n "${T}" | ssh-keygen -Y sign -f "${KEY}_$2" -n "${NAMESPACE}" -)
  curl -s -X POST "${GATEWAY}/${USR}/proxy/$1/$2" -H "DATA: ${D}" -d "${S}"
}

# main entrypoint
if [ -n "$1" ]; then
  case "$1" in
  help)
    cmd_help
    ;;
  register)
    cmd_special_register
    ;;
  status)
    cmd_generic "status"
    ;;
  launch)
    cmd_generic "launch"
    ;;
  destroy)
    cmd_generic "destroy"
    ;;
  ssh)
    cmd_special_ssh
    ;;
  peek)
    cmd_special_bridge "peek" "$2"
    ;;
  attack)
    cmd_special_bridge "attack" "$2"
    ;;
  proxy_register)
    cmd_proxy_special_register "$2"
    ;;
  proxy_login)
    cmd_proxy_generic "login" "$2"
    ;;
  reset)
    cmd_generic_admin "reset" "$2"
    ;;
  snapshot)
    cmd_generic "snapshot"
    ;;
  populate)
    cmd_generic "populate"
    ;;
  shutdown)
    cmd_generic "shutdown"
    ;;
  *)
    echo "unknown command, please see run '$0 help' for the help message"
    ;;
  esac
else
  cmd_help
fi
