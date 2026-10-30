# The fpm image supplies the calibrated ELF, but CMD below uses php -S.
# Keep this exact Alpine build and CLI-server worker model for the PoC.
FROM php:8.4.26-fpm-alpine3.23
COPY Public/ /app/
COPY Challenge/OperatorNote.txt /opt/workshop/OperatorNote.txt
COPY Challenge/Script01_CheckVault.php /opt/workshop/Script01_CheckVault.php
COPY Challenge/Script02_PrintFlag.sh /usr/local/bin/print-flag
COPY Challenge/Script03_Ledger.sh /usr/local/bin/ledger
RUN chmod 755 /usr/local/bin/print-flag /usr/local/bin/ledger && chmod 644 /opt/workshop/OperatorNote.txt
WORKDIR /app
EXPOSE 8000
CMD ["php", "-S", "0.0.0.0:8000", "-t", "/app"]
