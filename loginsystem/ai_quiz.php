<?php
session_start();

if (!isset($_SESSION['email'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit();
}

require_once 'api_config.php';

header('Content-Type: application/json');

$topics = ['phishing', 'ransomware', 'two-factor authentication', 'password security',
           'social engineering', 'VPN', 'encryption', 'malware', 'firewall', 'data breaches'];
$topic = $topics[array_rand($topics)];

$prompt = "Generate a cybersecurity multiple-choice quiz question about '{$topic}'. "
        . "Reply ONLY with a valid JSON object — no extra text:\n"
        . "{\n"
        . "  \"question\": \"the question\",\n"
        . "  \"options\": [\"A text\", \"B text\", \"C text\", \"D text\"],\n"
        . "  \"answer\": 0,\n"
        . "  \"explanation\": \"correct answer explanation under 20 words\"\n"
        . "}\n"
        . "The answer field is the 0-based index of the correct option.";

$payload = [
    'model'      => ANTHROPIC_MODEL,
    'max_tokens' => 220,
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
    'question'    => 'What does "2FA" stand for?',
    'options'     => ['Two-Factor Authentication', 'Two-File Access', 'Trusted Firewall Access', 'Two-Factor Authorization'],
    'answer'      => 0,
    'explanation' => '2FA adds a second verification step beyond just your password.'
];

if ($err) { echo json_encode($fallback); exit(); }

$result = json_decode($response, true);
if (isset($result['content'][0]['text'])) {
    $text = trim($result['content'][0]['text']);
    // Strip any markdown code fences
    $text = preg_replace('/^```(?:json)?\s*/i', '', $text);
    $text = preg_replace('/\s*```$/', '', $text);
    if (preg_match('/\{.*\}/s', $text, $m)) {
        $parsed = json_decode($m[0], true);
        if ($parsed
            && isset($parsed['question'], $parsed['options'], $parsed['answer'], $parsed['explanation'])
            && is_array($parsed['options'])
            && count($parsed['options']) === 4
        ) {
            echo json_encode($parsed);
            exit();
        }
    }
}

echo json_encode($fallback);
