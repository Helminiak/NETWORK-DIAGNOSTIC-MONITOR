#!/bin/sh
# Read-only discovery: no writes, installation, firmware flash, or network calls.
# Prints model/build/tool capabilities only. Does not read passwords, SSIDs or MACs.
set -eu
json_string() {
    printf '%s' "$1" | awk 'BEGIN{printf "\""}{gsub(/\\/,"\\\\");gsub(/\"/,"\\\"");gsub(/\r/,"");if(NR>1)printf "\\n";printf "%s",$0}END{printf "\""}'
}
read_key() { if command -v nvram >/dev/null 2>&1; then nvram get "$1" 2>/dev/null || :; fi; }
architecture=$(uname -m)
model=$(read_key productid)
variant=$(read_key odmpid)
build=$(read_key buildno)
extend=$(read_key extendno)
rc_support=$(read_key rc_support)
merlin_api=false
case " $rc_support " in *' am_addons '*) merlin_api=true;; esac
memory_kib=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || :)
case "$memory_kib" in ''|*[!0-9]*) memory_kib=null;; esac
printf '{"schemaVersion":1,"purpose":"READ_ONLY_FORK_CAPABILITIES","model":'
json_string "$model"
printf ',"variant":'; json_string "$variant"
printf ',"architecture":'; json_string "$architecture"
printf ',"build":'; json_string "$build"
printf ',"extend":'; json_string "$extend"
printf ',"addonsApiAdvertised":%s,"memoryKiB":%s,"tools":{' "$merlin_api" "$memory_kib"
separator=''
for name in sh awk sed ping traceroute curl wget nslookup dig tcpdump openssl flock timeout cru; do
    available=false
    if command -v "$name" >/dev/null 2>&1; then available=true; fi
    printf '%s"%s":%s' "$separator" "$name" "$available"
    separator=','
done
printf '},"deploymentReady":false}\n'
