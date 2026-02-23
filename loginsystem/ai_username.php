<?php
require_once 'api_config.php';

header('Content-Type: application/json');

$input = json_decode(file_get_contents('php://input'), true);
// Sanitize: only keep alphanumeric and underscores from the supplied base
$base  = isset($input['username']) ? preg_replace('/[^a-zA-Z0-9_]/', '', trim($input['username'])) : '';

if (strlen($base) < 3) {
    echo json_encode(['suggestions' => []]);
    exit();
}

$base = substr($base, 0, 20); // cap length sent to API

$prompt = "Based on the username '{$base}', suggest 3 creative, unique alternative usernames. "
        . "Rules: only lowercase letters, digits, and underscores; max 16 characters each; "
        . "must be different from '{$base}'. "
        . "Reply ONLY with a valid JSON array of 3 strings — no other text: "
        . "[\"suggestion1\", \"suggestion2\", \"suggestion3\"]";

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
    echo json_encode(['suggestions' => []]);
    exit();
}

$result = json_decode($response, true);
if (isset($result['content'][0]['text'])) {
    $parsed = json_decode(trim($result['content'][0]['text']), true);
    if (is_array($parsed) && count($parsed) > 0) {
        $clean = [];
        foreach ($parsed as $s) {
            $s = preg_replace('/[^a-z0-9_]/', '', strtolower((string)$s));
            if (strlen($s) >= 3 && strlen($s) <= 16) {
                $clean[] = $s;
            }
        }
        echo json_encode(['suggestions' => array_values($clean)]);
        exit();
    }
}

echo json_encode(['suggestions' => []]);
