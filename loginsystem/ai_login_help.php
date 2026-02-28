<?php
require_once 'api_config.php';

header('Content-Type: application/json');

$prompt = "A user just failed to log in to a website. "
        . "Give exactly 3 brief troubleshooting tips. "
        . "Reply ONLY with a valid JSON array of 3 strings, each under 12 words. "
        . "Example: [\"Double-check your email address for typos.\", \"Make sure Caps Lock is off.\", \"Try resetting your password.\"]";

$payload = [
    'model'      => ANTHROPIC_MODEL,
    'max_tokens' => 120,
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

$fallback = [
    'Double-check your email address for typos.',
    'Make sure Caps Lock is off.',
    'Try resetting your password if you forgot it.'
];

if ($err) {
    echo json_encode(['tips' => $fallback]);
    exit();
}

$result = json_decode($response, true);
if (isset($result['content'][0]['text'])) {
    $parsed = json_decode(trim($result['content'][0]['text']), true);
    if (is_array($parsed) && count($parsed) >= 1) {
        echo json_encode(['tips' => array_values($parsed)]);
        exit();
    }
}

echo json_encode(['tips' => $fallback]);
