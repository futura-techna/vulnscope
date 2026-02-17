#!/bin/bash

DOMAIN="vulnscope"
TOKEN="af5fc485-4f69-4ae2-a2c6-eec90472fec4"

echo url="https://www.duckdns.org/update?domains=$DOMAIN&token=$TOKEN&ip=" | curl -k -o ~/duckdns/duck.log -K -

crontab -e
*/5 * * * * ~/duckdns_update.sh >/dev/null 2>&1
