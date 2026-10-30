<?php
declare(strict_types=1);
// This runs inside the PHP container after the web foothold. The vault key comes from a runtime volume, not from source control. The guided PoC uses the default wallet route; the ledger command can request records first.
$route = $argv[1] ?? 'wallet';
if (!in_array($route, ['records', 'wallet'], true)) {
    fwrite(STDERR, "Usage: ledger [records|wallet]\n");
    exit(2);
}
$key = trim(file_get_contents('/opt/workshop/access/vault.key'));
// Only the PHP container shares the private network with vault:9000.
$context = stream_context_create(['http' => ['header' => "X-Vault-Key: {$key}\r\n", 'timeout' => 3]]);
$response = file_get_contents("http://vault:9000/{$route}", false, $context);
if ($response === false) { fwrite(STDERR, "Vault request failed\n"); exit(1); }
echo $response, PHP_EOL;
