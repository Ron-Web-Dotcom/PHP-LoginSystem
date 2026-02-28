<?php
require_once 'api_config.php';

header('Content-Type: application/json');

$input    = json_decode(file_get_contents('php://input'), true);
$question = isset($input['question']) ? mb_substr(trim($input['question']), 0, 200) : '';

if ($question === '') {
    echo json_encode(['answer' => '']);
    exit();
}

$prompt = "You are a concise FAQ assistant for a simple PHP web login system. "
        . "Answer ONLY questions about: registering an account, logging in, passwords, or usernames on this site. "
        . "Keep answers under 45 words and be friendly. "
        . "If the question is unrelated, say exactly: 'I can only help with login and registration questions for this site.' "
        . "\n\nQuestion: " . $question;

$payload = [
    'model'      => ANTHROPIC_MODEL,
    'max_tokens' => 100,
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
    echo json_encode(['answer' => 'Sorry, I could not connect right now. Please try again.']);
    exit();
}

$result = json_decode($response, true);
$answer = isset($result['content'][0]['text'])
        ? trim($result['content'][0]['text'])
        : 'Sorry, I could not generate an answer right now.';

echo json_encode(['answer' => $answer]);
