#!/usr/bin/env bash
# Download and install GRE over FOU Manager from GitHub.
set -euo pipefail
REPOSITORY='admin6501/gre-fou-manager'
REF='main'
NO_DEPS=0
usage() {
  cat <<'HELP'
GRE over FOU Manager installer
Usage: sudo bash install.sh [--ref BRANCH_TAG_OR_COMMIT] [--no-deps]
Default ref: main. Use a commit SHA for a reproducible install.
Requires Linux, systemd, root, and kernel GRE/FOU support.
--no-deps: use dependencies already installed on the server.
HELP
}
while (($#)); do
  case "$1" in
    --ref) [[ $# -ge 2 ]] || { echo 'Missing --ref argument' >&2; exit 2; }; REF=$2; shift 2 ;;
    --no-deps) NO_DEPS=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
[[ "$REF" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || { echo 'Invalid Git ref' >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo 'Run this installer with sudo or as root.' >&2; exit 1; }
[[ -d /run/systemd/system ]] || { echo 'An active systemd host is required.' >&2; exit 1; }
if ! command -v curl >/dev/null || ! command -v python3 >/dev/null || ! command -v sha256sum >/dev/null; then
  if ((NO_DEPS)); then
    echo '--no-deps requires curl, python3 and sha256sum to be installed.' >&2; exit 1
  elif command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
    apt-get update
    apt-get install -y curl ca-certificates python3 coreutils
  elif command -v dnf >/dev/null; then
    dnf install -y curl ca-certificates python3 coreutils
  else
    echo 'Install curl, ca-certificates, python3 and coreutils first.' >&2; exit 1
  fi
fi
umask 077
INSTALL_TEMP=$(mktemp -d)
trap 'rm -rf -- "$INSTALL_TEMP"' EXIT
BASE_URL="https://raw.githubusercontent.com/$REPOSITORY/$REF"
fetch() {
  curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 120 --retry 2 "$BASE_URL/$1" -o "$INSTALL_TEMP/$1"
}
fetch gre-fou-manager.sh
fetch checksums.sha256
python3 - "$INSTALL_TEMP/checksums.sha256" <<'PY'
import pathlib,re,sys
text=pathlib.Path(sys.argv[1]).read_text()
if not re.fullmatch(r'[0-9a-f]{64}  gre-fou-manager\.sh\n?',text):
    sys.exit('Invalid checksum manifest; installation cancelled.')
PY
(cd "$INSTALL_TEMP" && sha256sum --check --strict checksums.sha256)
bash -n "$INSTALL_TEMP/gre-fou-manager.sh"
if ((NO_DEPS)); then
  bash "$INSTALL_TEMP/gre-fou-manager.sh" install --no-deps
else
  bash "$INSTALL_TEMP/gre-fou-manager.sh" install
fi
