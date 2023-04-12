#!/bin/bash

# Delete keys from the Hockeypuck postgres database by fingerprint

set -euo pipefail

if [[ ! ${1:-} ]]; then
    cat <<EOF
Usage: $0 FINGERPRINT [FINGERPRINT ...]
       $0 -f FINGERPRINT_FILE

If FINGERPRINT_FILE is given, it should contain one fingerprint per line, folded to lowercase.
EOF
    exit 1
fi

# Uncomment and edit one of the below for your postgres installation
# for docker-compose/standalone default configuration
SQLCMD="docker exec -i standalone_postgres_1 psql hkp -U hkp"
# for docker-compose/dev default configuration
#SQLCMD="docker exec -i hockeypuck_postgres_1 psql hkp -U docker"
# for non-docker postgres, e.g.
#SQLCMD="psql hkp -U hkp"

reverse_fp() {
  # print the input string in reverse order
  input=$1
  while [[ $input ]]; do
    echo -n "${input: -1}"
    input="${input%?}"
  done
  echo
}

reverse_fplist() {
  local rfplist
  for fp in "$@"; do
    rfp=$(reverse_fp "${fp,,}") # fold to lowercase and reverse
    if [[ ${rfplist:-} ]]; then
        rfplist="$rfplist, '$rfp'"
    else
        rfplist="'$rfp'"
    fi
  done
  echo "$rfplist"
}

if [[ $1 == "-f" ]]; then
  [[ ${2:-} ]] || usage
  $SQLCMD -c 'create table if not exists bad_fps (fingerprint text primary key);'
  $SQLCMD -c '\copy bad_fps from stdin csv' < "$2"
  $SQLCMD -c '
    delete from subkeys k using bad_fps b where k.rfingerprint = reverse(b.fingerprint);
    alter table subkeys drop constraint subkeys_rfingerprint_fkey;
    delete from    keys k using bad_fps b where k.rfingerprint = reverse(b.fingerprint);
    alter table subkeys add foreign key (rfingerprint) references keys(rfingerprint);
    drop table bad_fps;
  '
else
  rfplist=$(reverse_fplist "$@")
  $SQLCMD -c "
    delete from subkeys where rfingerprint in (${rfplist});
    delete from    keys where rfingerprint in (${rfplist});
  "
fi
