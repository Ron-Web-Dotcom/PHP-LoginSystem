<?php
require_once 'api_config.php';

header('Content-Type: application/json');

$input = json_decode(file_get_contents('php://input'), true);
$email = isset($input['email']) ? trim($input['email']) : '';

if ($email === '') {
    echo json_encode(['status' => '', 'message' => '']);
    exit();
}

// Basic format check first — no API call needed for obviously invalid addresses
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['status' => 'invalid', 'message' => 'Not a valid email address format.']);
    exit();
}

// Only send the domain to the AI — the local part (username) never leaves this server
$domain = explode('@', $email)[1];

$prompt = "Is the email domain '{$domain}' a legitimate, reputable email provider "
        . "(e.g. gmail.com, yahoo.com, outlook.com, a real company domain)?\n"
        . "Reply ONLY with a valid JSON object — no extra text:\n"
        . "{\"status\": \"good|suspicious|disposable\", \"message\": \"reason in under 8 words\"}";

$payload = [
    'model'      => ANTHROPIC_MODEL,
    'max_tokens' => 60,
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
    echo json_encode(['status' => '', 'message' => '']);
    exit();
}

$result = json_decode($response, true);
if (isset($result['content'][0]['text'])) {
    $parsed = json_decode(trim($result['content'][0]['text']), true);
    if ($parsed && isset($parsed['status'], $parsed['message'])) {
        echo json_encode($parsed);
        exit();
    }
}

echo json_encode(['status' => 'good', 'message' => '']);
