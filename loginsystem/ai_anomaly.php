<?php
/**
 * AI Anomaly Detector — POST endpoint.
 * Analyses login patterns for the current user and returns anomalies via Claude.
 * Called by homepage.php on-demand (button click).
 */
require_once 'auth_check.php';
require_once 'api_config.php';

header('Content-Type: application/json');

$email = $_SESSION['email'];
$con   = mysqli_connect('localhost', 'root', '', 'system');

// ── Gather last-30-day login patterns ────────────────────────────────────────
$patterns = [
    'hour_distribution' => array_fill(0, 24, 0),  // logins per hour of day
    'day_distribution'  => array_fill(0, 7, 0),   // logins per weekday
    'unique_ips'        => [],
    'sessions_last30d'  => 0,
    'failed_last30d'    => 0,
];

$since = date('Y-m-d H:i:s', strtotime('-30 days'));

$tsl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_session_log'");
if ($tsl && mysqli_num_rows($tsl) > 0) {
    $stmt = mysqli_prepare($con,
        "SELECT login_time, ip FROM tbl_session_log
         WHERE email = ? AND login_time >= ? ORDER BY login_time DESC"
    );
    mysqli_stmt_bind_param($stmt, 'ss', $email, $since);
    mysqli_stmt_execute($stmt);
    $res = mysqli_stmt_get_result($stmt);
    $ips = [];
    while ($row = mysqli_fetch_assoc($res)) {
        $h = (int) date('G', strtotime($row['login_time']));
        $d = (int) date('N', strtotime($row['login_time'])) - 1; // 0=Mon
        $patterns['hour_distribution'][$h]++;
        $patterns['day_distribution'][$d]++;
        $patterns['sessions_last30d']++;
        if ($row['ip']) $ips[$row['ip']] = true;
    }
    mysqli_stmt_close($stmt);
    $patterns['unique_ips'] = array_keys($ips);
}

$tla = mysqli_query($con, "SHOW TABLES LIKE 'tbl_login_attempts'");
if ($tla && mysqli_num_rows($tla) > 0) {
    $stmt2 = mysqli_prepare($con,
        "SELECT COUNT(*) FROM tbl_login_attempts WHERE email = ? AND attempt_time >= ?"
    );
    mysqli_stmt_bind_param($stmt2, 'ss', $email, $since);
    mysqli_stmt_execute($stmt2);
    mysqli_stmt_bind_result($stmt2, $fc);
    mysqli_stmt_fetch($stmt2);
    mysqli_stmt_close($stmt2);
    $patterns['failed_last30d'] = (int)$fc;
}
mysqli_close($con);

// ── Ask Claude ────────────────────────────────────────────────────────────────
$prompt = "You are a security analyst. A user has the following login patterns over the last 30 days:\n\n"
    . json_encode($patterns, JSON_PRETTY_PRINT)
    . "\n\nIdentify any security anomalies or unusual patterns."
    . " Respond with a JSON object exactly like this:\n"
    . "{\n"
    . "  \"anomalies\": [\n"
    . "    { \"type\": \"<short_type>\", \"description\": \"<1-2 sentence explanation>\", \"severity\": \"high|medium|low\" }\n"
    . "  ],\n"
    . "  \"summary\": \"<2-3 sentence overall assessment>\"\n"
    . "}\n"
    . "If no anomalies are found, return an empty anomalies array with a positive summary.\n"
    . "Respond with ONLY valid JSON, no markdown, no extra text.";

$payload = json_encode([
    'model'      => ANTHROPIC_MODEL,
    'max_tokens' => 500,
    'messages'   => [['role' => 'user', 'content' => $prompt]],
]);

$ch = curl_init(ANTHROPIC_API_URL);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST           => true,
    CURLOPT_POSTFIELDS     => $payload,
    CURLOPT_HTTPHEADER     => [
        'Content-Type: application/json',
        'x-api-key: ' . ANTHROPIC_API_KEY,
        'anthropic-version: 2023-06-01',
    ],
    CURLOPT_TIMEOUT        => 20,
]);
$resp = curl_exec($ch);
$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if (!$resp || $code !== 200) {
    echo json_encode(['error' => 'AI service unavailable', 'anomalies' => [], 'summary' => '']);
    exit();
}

$decoded = json_decode($resp, true);
$text    = $decoded['content'][0]['text'] ?? '{}';

// Strip any markdown fencing
$text = preg_replace('/^```(?:json)?\s*/m', '', $text);
$text = preg_replace('/```\s*$/m', '', $text);

$result = json_decode(trim($text), true);
if (!$result) {
    $result = ['anomalies' => [], 'summary' => 'Could not parse AI response.'];
}

echo json_encode($result);
