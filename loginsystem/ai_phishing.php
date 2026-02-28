<?php
session_start();

if (!isset($_SESSION['email'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit();
}

require_once 'api_config.php';

header('Content-Type: application/json');

$input = json_decode(file_get_contents('php://input'), true);
$text  = trim($input['text'] ?? '');

if ($text === '') {
    echo json_encode(['error' => 'No input provided']);
    exit();
}

// Limit input length to avoid excessive token usage
if (strlen($text) > 2000) {
    $text = substr($text, 0, 2000);
}

$prompt = "You are a cybersecurity expert. Analyse the following text for phishing or scam indicators.\n"
        . "Text:\n\"\"\"\n" . $text . "\n\"\"\"\n\n"
        . "Reply ONLY with a valid JSON object — no markdown, no extra text:\n"
        . "{\"verdict\":\"phishing\",\"confidence\":\"high\",\"reasons\":[\"specific observation\"],\"advice\":\"one sentence\"}\n"
        . "Rules:\n"
        . "- verdict: exactly one of: phishing, suspicious, safe\n"
        . "- confidence: exactly one of: high, medium, low\n"
        . "- reasons: array of 1–3 specific observations about this text\n"
        . "- advice: single actionable sentence for the user";

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
    'verdict'    => 'suspicious',
    'confidence' => 'low',
    'reasons'    => ['Analysis unavailable — treat with caution.'],
    'advice'     => 'When in doubt, do not click links or share personal information.'
];

if ($err) { echo json_encode($fallback); exit(); }

$result = json_decode($response, true);
if (isset($result['content'][0]['text'])) {
    $raw = trim($result['content'][0]['text']);
    // Strip any accidental markdown fences
    $raw = preg_replace('/^```(?:json)?\s*/i', '', $raw);
    $raw = preg_replace('/\s*```$/',           '', $raw);
    if (preg_match('/\{.*\}/s', $raw, $m)) {
        $parsed = json_decode($m[0], true);
        if ($parsed
            && isset($parsed['verdict'], $parsed['confidence'], $parsed['reasons'], $parsed['advice'])
            && in_array($parsed['verdict'],    ['phishing', 'suspicious', 'safe'])
            && in_array($parsed['confidence'], ['high', 'medium', 'low'])
            && is_array($parsed['reasons'])
        ) {
            echo json_encode($parsed);
            exit();
        }
    }
}

echo json_encode($fallback);
