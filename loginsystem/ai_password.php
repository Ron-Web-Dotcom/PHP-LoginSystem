<?php
require_once 'api_config.php';

header('Content-Type: application/json');

$input    = json_decode(file_get_contents('php://input'), true);
$password = isset($input['password']) ? $input['password'] : '';

if ($password === '') {
    echo json_encode(['strength' => '', 'message' => '']);
    exit();
}

// Derive only anonymous characteristics — the raw password is never sent to the API
$length     = strlen($password);
$hasUpper   = preg_match('/[A-Z]/', $password)      ? 'yes' : 'no';
$hasLower   = preg_match('/[a-z]/', $password)      ? 'yes' : 'no';
$hasDigit   = preg_match('/[0-9]/', $password)      ? 'yes' : 'no';
$hasSpecial = preg_match('/[^A-Za-z0-9]/', $password) ? 'yes' : 'no';

$prompt = "Evaluate password strength based only on these characteristics:\n"
        . "- Length: {$length} characters\n"
        . "- Uppercase letters: {$hasUpper}\n"
        . "- Lowercase letters: {$hasLower}\n"
        . "- Numbers: {$hasDigit}\n"
        . "- Special characters: {$hasSpecial}\n\n"
        . "Reply with ONLY a valid JSON object — no extra text:\n"
        . "{\"strength\": \"weak|fair|strong|very strong\", \"message\": \"one short actionable tip\"}";

$payload = [
    'model'      => ANTHROPIC_MODEL,
    'max_tokens' => 100,
    'messages'   => [
        ['role' => 'user', 'content' => $prompt]
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
    echo json_encode(['strength' => '', 'message' => 'Could not check strength.']);
    exit();
}

$result = json_decode($response, true);

if (isset($result['content'][0]['text'])) {
    $text   = trim($result['content'][0]['text']);
    $parsed = json_decode($text, true);
    if ($parsed && isset($parsed['strength'], $parsed['message'])) {
        echo json_encode($parsed);
    } else {
        echo json_encode(['strength' => '', 'message' => 'Could not parse response.']);
    }
} else {
    echo json_encode(['strength' => '', 'message' => 'API error.']);
}
