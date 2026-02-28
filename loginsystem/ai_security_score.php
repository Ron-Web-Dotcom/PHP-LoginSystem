<?php
require_once 'auth_check.php';
require_once 'api_config.php';

header('Content-Type: application/json');

$email = $_SESSION['email'];
$con   = mysqli_connect('localhost', 'root', '', 'system');

// Gather account security signals
$totpEnabled   = false;
$failedLast7d  = 0;
$sessionsLast30d = 0;
$lastLogin     = null;
$isLocked      = false;

// 2FA status
$r = mysqli_query($con,
    "SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA='system' AND TABLE_NAME='tbl_signup' AND COLUMN_NAME='totp_enabled'"
);
if ($r && mysqli_num_rows($r) > 0) {
    $s = mysqli_prepare($con, "SELECT totp_enabled FROM tbl_signup WHERE email = ?");
    mysqli_stmt_bind_param($s, 's', $email);
    mysqli_stmt_execute($s);
    mysqli_stmt_bind_result($s, $te);
    mysqli_stmt_fetch($s);
    mysqli_stmt_close($s);
    $totpEnabled = (bool) $te;
}

// Failed attempts
$tcheck = mysqli_query($con, "SHOW TABLES LIKE 'tbl_login_attempts'");
if ($tcheck && mysqli_num_rows($tcheck) > 0) {
    $w7 = date('Y-m-d H:i:s', strtotime('-7 days'));
    $s  = mysqli_prepare($con,
        "SELECT COUNT(*) FROM tbl_login_attempts WHERE email = ? AND attempt_time >= ?"
    );
    mysqli_stmt_bind_param($s, 'ss', $email, $w7);
    mysqli_stmt_execute($s);
    mysqli_stmt_bind_result($s, $failedLast7d);
    mysqli_stmt_fetch($s);
    mysqli_stmt_close($s);

    $w15 = date('Y-m-d H:i:s', strtotime('-15 minutes'));
    $s2  = mysqli_prepare($con,
        "SELECT COUNT(*) FROM tbl_login_attempts WHERE email = ? AND attempt_time >= ?"
    );
    mysqli_stmt_bind_param($s2, 'ss', $email, $w15);
    mysqli_stmt_execute($s2);
    mysqli_stmt_bind_result($s2, $recentCount);
    mysqli_stmt_fetch($s2);
    mysqli_stmt_close($s2);
    $isLocked = $recentCount >= 5;
}

// Sessions
$tcheck2 = mysqli_query($con, "SHOW TABLES LIKE 'tbl_session_log'");
if ($tcheck2 && mysqli_num_rows($tcheck2) > 0) {
    $w30 = date('Y-m-d H:i:s', strtotime('-30 days'));
    $s3  = mysqli_prepare($con,
        "SELECT COUNT(*), MAX(login_time) FROM tbl_session_log WHERE email = ? AND login_time >= ?"
    );
    mysqli_stmt_bind_param($s3, 'ss', $email, $w30);
    mysqli_stmt_execute($s3);
    mysqli_stmt_bind_result($s3, $sessionsLast30d, $lastLogin);
    mysqli_stmt_fetch($s3);
    mysqli_stmt_close($s3);
}

mysqli_close($con);

$prompt =
    "You are a security analyst evaluating an account's security posture. "
  . "Based on the data below, produce a JSON security score report.\n\n"
  . "Account data:\n"
  . "- 2FA/TOTP enabled: " . ($totpEnabled ? 'yes' : 'no') . "\n"
  . "- Failed login attempts in last 7 days: {$failedLast7d}\n"
  . "- Currently locked out: " . ($isLocked ? 'yes' : 'no') . "\n"
  . "- Successful logins in last 30 days: {$sessionsLast30d}\n"
  . "- Last login: " . ($lastLogin ?? 'never recorded') . "\n\n"
  . "Reply ONLY with valid JSON, no extra text:\n"
  . "{\"score\":85,\"grade\":\"B\",\"color\":\"#84cc16\","
  . "\"summary\":\"one sentence summary\","
  . "\"recommendations\":[\"specific rec 1\",\"specific rec 2\"]}\n"
  . "Rules:\n"
  . "- score: integer 0–100\n"
  . "- grade: one of A, B, C, D, F\n"
  . "- color: hex colour matching the grade (A=#22c55e, B=#84cc16, C=#f97316, D=#ef4444, F=#dc2626)\n"
  . "- recommendations: 2–3 specific, actionable items";

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

if ($err) { echo json_encode(['error' => 'API unavailable']); exit(); }

$result = json_decode($response, true);
if (isset($result['content'][0]['text'])) {
    $raw = trim($result['content'][0]['text']);
    $raw = preg_replace('/^```(?:json)?\s*/i', '', $raw);
    $raw = preg_replace('/\s*```$/',           '', $raw);
    if (preg_match('/\{.*\}/s', $raw, $m)) {
        $parsed = json_decode($m[0], true);
        if ($parsed && isset($parsed['score'], $parsed['grade'])) {
            echo json_encode($parsed);
            exit();
        }
    }
}

echo json_encode(['error' => 'Parse error']);
