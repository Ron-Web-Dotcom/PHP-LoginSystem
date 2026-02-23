<?php
session_start();

// Only logged-in users may use the chat
if (!isset($_SESSION['email'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit();
}

require_once 'api_config.php';

header('Content-Type: application/json');

$input   = json_decode(file_get_contents('php://input'), true);
$message = isset($input['message']) ? trim($input['message']) : '';

if ($message === '') {
    echo json_encode(['error' => 'Message cannot be empty']);
    exit();
}

// Truncate to avoid abuse
$message = mb_substr($message, 0, 1000);

$payload = [
    'model'      => ANTHROPIC_MODEL,
    'max_tokens' => 512,
    'system'     => 'You are a friendly and concise AI assistant embedded in a web application. Keep every reply under 150 words.',
    'messages'   => [
        ['role' => 'user', 'content' => $message]
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

if ($err) {
    echo json_encode(['error' => 'Network error. Please try again.']);
    exit();
}

$result = json_decode($response, true);

if (isset($result['content'][0]['text'])) {
    echo json_encode(['reply' => $result['content'][0]['text']]);
} else {
    $msg = isset($result['error']['message']) ? $result['error']['message'] : 'Unknown error';
    echo json_encode(['error' => $msg]);
}
