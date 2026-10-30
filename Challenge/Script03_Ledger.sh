#!/bin/sh
# Short command for the selected-command PoC's small payload carrier.
# The PHP helper reads the runtime key and contacts the private vault.
exec php /opt/workshop/Script01_CheckVault.php "${1:-records}"
