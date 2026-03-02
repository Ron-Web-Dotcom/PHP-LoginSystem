<?php
/**
 * HIBP k-Anonymity password breach check.
 * POST { "password": "..." } → { "breached": bool, "count": int }
 * Uses the HaveIBeenPwned range API — only the first 5 SHA-1 chars leave the server.
 */
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'POST required']);
    exit();
}

$body     = json_decode(file_get_contents('php://input'), true);
$password = $body['password'] ?? '';

if ($password === '') {
    echo json_encode(['breached' => false, 'count' => 0]);
    exit();
}

$sha1   = strtoupper(sha1($password));
$prefix = substr($sha1, 0, 5);
$suffix = substr($sha1, 5);

$ctx = stream_context_create([
    'http' => [
        'timeout'     => 5,
        'method'      => 'GET',
        'header'      => "User-Agent: PHP-LoginSystem/1.0\r\nAdd-Padding: true\r\n",
    ],
    'ssl'  => ['verify_peer' => true],
]);

$raw = @file_get_contents("https://api.pwnedpasswords.com/range/{$prefix}", false, $ctx);
if ($raw === false) {
    // HIBP unreachable — fail open (don't block the user)
    echo json_encode(['breached' => false, 'count' => 0, 'error' => 'hibp_unavailable']);
    exit();
}

$count = 0;
foreach (explode("\n", $raw) as $line) {
    $line = trim($line);
    if ($line === '') continue;
    [$lineSuffix, $lineCount] = explode(':', $line, 2);
    if (strtoupper($lineSuffix) === $suffix) {
        $count = (int) $lineCount;
        break;
    }
}

echo json_encode(['breached' => $count > 0, 'count' => $count]);
