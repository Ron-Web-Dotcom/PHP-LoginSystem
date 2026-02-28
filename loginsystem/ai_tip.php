<?php
session_start();

// Only logged-in users may fetch a tip
if (!isset($_SESSION['email'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit();
}

require_once 'api_config.php';

header('Content-Type: application/json');

// Return cached tip for this session so we only call the API once per login
if (!empty($_SESSION['security_tip'])) {
    echo json_encode(['tip' => $_SESSION['security_tip']]);
    exit();
}

$payload = [
    'model'      => ANTHROPIC_MODEL,
    'max_tokens' => 80,
    'messages'   => [
        ['role' => 'user', 'content' => 'Give one practical, specific online security tip in under 30 words. Only the tip text — no label, no preamble.']
    ]
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

$fallback = 'Enable two-factor authentication on every account that supports it.';

if ($err) {
    echo json_encode(['tip' => $fallback]);
    exit();
}

$result = json_decode($response, true);
$tip    = isset($result['content'][0]['text'])
        ? trim($result['content'][0]['text'])
        : $fallback;

$_SESSION['security_tip'] = $tip;
echo json_encode(['tip' => $tip]);
