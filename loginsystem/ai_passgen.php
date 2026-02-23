<?php
require_once 'api_config.php';

header('Content-Type: application/json');

$prompt = "Generate one strong, memorable password passphrase. "
        . "Format: three unrelated lowercase words separated by hyphens, followed by a 2-digit number and one symbol from !@#$%. "
        . "Example: river-lamp-wolf44! "
        . "Return ONLY the password string — no quotes, no explanation.";

$payload = [
    'model'      => ANTHROPIC_MODEL,
    'max_tokens' => 30,
    'messages'   => [['role' => 'user', 'content' => $prompt]]
];

$ch = curl_init(ANTHROPIC_API_URL);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST           => true,
    CURLOPT_POSTFIELDS     => json_encode($payload),
    CURLOPT_HTTPHEADER     => [
        'Content-Type: application/json',
        'x-api-key: ' . ANTHROPIC_API_KEY,
        'anthropic-version: 2023-06-01'
    ]
]);

$response = curl_exec($ch);
$err      = curl_error($ch);
curl_close($ch);

if ($err) {
    echo json_encode(['password' => '']);
    exit();
}

$result = json_decode($response, true);
$pw = isset($result['content'][0]['text'])
   ? trim($result['content'][0]['text'], " \t\n\r\"'`")
   : '';

echo json_encode(['password' => $pw]);
