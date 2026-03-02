<?php
/**
 * Admin-only AI Password / Security Audit.
 * Returns JSON with aggregate user-base security stats and Claude's assessment.
 */
require_once 'auth_check.php';
require_once 'api_config.php';

header('Content-Type: application/json');

if (empty($_SESSION['is_admin'])) {
    http_response_code(403);
    echo json_encode(['error' => 'Forbidden']);
    exit();
}

$con = mysqli_connect('localhost', 'root', '', 'system');

// ── Aggregate stats ───────────────────────────────────────────────────────────
$stats = [
    'total_users'       => 0,
    'with_2fa'          => 0,
    'pct_2fa'           => 0,
    'admin_count'       => 0,
    'locked_now'        => 0,
    'failed_total_7d'   => 0,
    'unique_ips_all'    => 0,
    'backup_code_users' => 0,
];

// Total users & 2FA
$r = mysqli_query($con,
    "SELECT COUNT(*) total, SUM(COALESCE(totp_enabled,0)) with2fa, SUM(COALESCE(is_admin,0)) admins
     FROM tbl_signup"
);
if ($r && $row = mysqli_fetch_assoc($r)) {
    $stats['total_users'] = (int)$row['total'];
    $stats['with_2fa']    = (int)$row['with2fa'];
    $stats['admin_count'] = (int)$row['admins'];
    $stats['pct_2fa']     = $stats['total_users']
        ? round($stats['with_2fa'] / $stats['total_users'] * 100, 1) : 0;
}

// Currently locked accounts
$tla = mysqli_query($con, "SHOW TABLES LIKE 'tbl_login_attempts'");
if ($tla && mysqli_num_rows($tla) > 0) {
    $win = date('Y-m-d H:i:s', strtotime('-15 minutes'));
    $lr  = mysqli_query($con,
        "SELECT COUNT(DISTINCT email) FROM tbl_login_attempts
         WHERE attempt_time >= '{$win}'
         GROUP BY email HAVING COUNT(*) >= 5"
    );
    $stats['locked_now'] = $lr ? mysqli_num_rows($lr) : 0;

    // Failed last 7 days
    $w7 = date('Y-m-d H:i:s', strtotime('-7 days'));
    $f7 = mysqli_query($con,
        "SELECT COUNT(*) c FROM tbl_login_attempts WHERE attempt_time >= '{$w7}'"
    );
    if ($f7 && $fr = mysqli_fetch_assoc($f7)) {
        $stats['failed_total_7d'] = (int)$fr['c'];
    }
}

// Unique IPs (last 30 days)
$tsl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_session_log'");
if ($tsl && mysqli_num_rows($tsl) > 0) {
    $w30 = date('Y-m-d H:i:s', strtotime('-30 days'));
    $ir  = mysqli_query($con,
        "SELECT COUNT(DISTINCT ip) c FROM tbl_session_log WHERE login_time >= '{$w30}'"
    );
    if ($ir && $irow = mysqli_fetch_assoc($ir)) {
        $stats['unique_ips_all'] = (int)$irow['c'];
    }
}

// Backup code users
$tbc = mysqli_query($con, "SHOW TABLES LIKE 'tbl_backup_codes'");
if ($tbc && mysqli_num_rows($tbc) > 0) {
    $bcr = mysqli_query($con,
        "SELECT COUNT(DISTINCT email) c FROM tbl_backup_codes WHERE used_at IS NULL"
    );
    if ($bcr && $brow = mysqli_fetch_assoc($bcr)) {
        $stats['backup_code_users'] = (int)$brow['c'];
    }
}

mysqli_close($con);

// ── Ask Claude ────────────────────────────────────────────────────────────────
$prompt = "You are a security auditor reviewing a web application's user-base security posture.\n"
    . "Aggregate statistics:\n" . json_encode($stats, JSON_PRETTY_PRINT) . "\n\n"
    . "Provide a security audit with:\n"
    . "1. An overall_grade (A/B/C/D/F)\n"
    . "2. An overall_score out of 100\n"
    . "3. A brief summary (2-3 sentences)\n"
    . "4. Up to 5 issues, each with { severity: high|medium|low, description: string }\n"
    . "5. Up to 5 recommendations (strings)\n"
    . "Respond with ONLY valid JSON:\n"
    . "{ \"overall_grade\": \"B\", \"overall_score\": 72, \"summary\": \"...\","
    . " \"issues\": [...], \"recommendations\": [...] }";

$payload = json_encode([
    'model'      => ANTHROPIC_MODEL,
    'max_tokens' => 700,
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
    CURLOPT_TIMEOUT => 20,
]);
$resp = curl_exec($ch);
$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

$audit = ['overall_grade' => '?', 'overall_score' => 0, 'summary' => '', 'issues' => [], 'recommendations' => []];
if ($resp && $code === 200) {
    $d    = json_decode($resp, true);
    $text = $d['content'][0]['text'] ?? '{}';
    $text = preg_replace('/^```(?:json)?\s*/m', '', $text);
    $text = preg_replace('/```\s*$/m', '', $text);
    $parsed = json_decode(trim($text), true);
    if ($parsed) $audit = $parsed;
}

echo json_encode(['stats' => $stats, 'audit' => $audit]);
