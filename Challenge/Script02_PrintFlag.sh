#!/bin/sh
# The exploit's fixed command invokes this once. The proof comes from the
# private vault through the PHP container's network and runtime key mount.
exec php /opt/workshop/Script01_CheckVault.php
