<?php
/**
 * Server-side IP geolocation proxy.
 * GET ?ip=1.2.3.4 → { "city": "...", "country": "...", "countryCode": "...", "flag": "🇺🇸" }
 * Uses ip-api.com (free, no key needed for non-commercial use).
 */
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');

$ip = $_GET['ip'] ?? '';

// Basic validation
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    echo json_encode(['city' => '', 'country' => '', 'flag' => '']);
    exit();
}

// Private / reserved ranges → show as Local
if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
    echo json_encode(['city' => 'Local Network', 'country' => '', 'countryCode' => '', 'flag' => '🏠']);
    exit();
}

$ctx  = stream_context_create(['http' => ['timeout' => 4]]);
$resp = @file_get_contents(
    "http://ip-api.com/json/{$ip}?fields=country,city,countryCode",
    false,
    $ctx
);

if ($resp === false) {
    echo json_encode(['city' => '', 'country' => '', 'flag' => '']);
    exit();
}

$data = json_decode($resp, true);
$flag = '';
if (!empty($data['countryCode'])) {
    $code = strtoupper($data['countryCode']);
    $chars = [];
    foreach (str_split($code) as $c) {
        $chars[] = mb_chr(ord($c) - ord('A') + 0x1F1E6, 'UTF-8');
    }
    $flag = implode('', $chars);
}

echo json_encode([
    'city'        => $data['city']        ?? '',
    'country'     => $data['country']     ?? '',
    'countryCode' => $data['countryCode'] ?? '',
    'flag'        => $flag,
]);
