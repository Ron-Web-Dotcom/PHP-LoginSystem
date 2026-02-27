<?php
session_start();

if (!isset($_SESSION['email'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit();
}

require_once 'api_config.php';

header('Content-Type: application/json');

// Cache per session so the API is called only once per login
if (!empty($_SESSION['threat_briefing'])) {
    echo json_encode($_SESSION['threat_briefing']);
    exit();
}

$prompt = "Pick one specific cyber threat from this list and vary it each call: "
        . "phishing, ransomware, credential stuffing, man-in-the-middle, keylogging, "
        . "SQL injection, brute force, social engineering, spyware, zero-day exploit.\n"
        . "Reply ONLY with a valid JSON object — no extra text:\n"
        . "{\"threat\": \"Threat Name\", \"description\": \"what it is in under 18 words\", \"tip\": \"how to stay safe in under 14 words\"}";

$payload = [
    'model'      => ANTHROPIC_MODEL,
    'max_tokens' => 110,
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
    'threat'      => 'Phishing',
    'description' => 'Attackers impersonate trusted sources to steal your credentials via fake emails.',
    'tip'         => 'Never click login links in emails — go directly to the website.'
];

if ($err) { echo json_encode($fallback); exit(); }

$result = json_decode($response, true);
if (isset($result['content'][0]['text'])) {
    $text = trim($result['content'][0]['text']);
    $text = preg_replace('/^```(?:json)?\s*/i', '', $text);
    $text = preg_replace('/\s*```$/', '', $text);
    if (preg_match('/\{.*\}/s', $text, $m)) {
        $parsed = json_decode($m[0], true);
        if ($parsed && isset($parsed['threat'], $parsed['description'], $parsed['tip'])) {
            $_SESSION['threat_briefing'] = $parsed;
            echo json_encode($parsed);
            exit();
        }
    }
}

$_SESSION['threat_briefing'] = $fallback;
echo json_encode($fallback);
