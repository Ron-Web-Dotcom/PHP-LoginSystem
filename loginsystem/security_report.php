<?php
require_once 'auth_check.php';
require_once 'api_config.php';

$email = $_SESSION['email'];
$con   = mysqli_connect('localhost', 'root', '', 'system');

// ── Gather account data ──────────────────────────────────────────────────────
$data = ['email' => $email, 'totp_enabled' => false, 'is_admin' => false,
         'total_logins' => 0, 'failed_7d' => 0, 'unique_ips' => 0,
         'last_login' => null, 'backup_codes_remaining' => 0];

$st = mysqli_prepare($con, "SELECT is_admin, totp_enabled FROM tbl_signup WHERE email = ?");
mysqli_stmt_bind_param($st, 's', $email);
mysqli_stmt_execute($st);
mysqli_stmt_bind_result($st, $ia, $te);
mysqli_stmt_fetch($st);
mysqli_stmt_close($st);
$data['is_admin']      = (bool) $ia;
$data['totp_enabled']  = (bool) $te;

$tsl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_session_log'");
if ($tsl && mysqli_num_rows($tsl) > 0) {
    $s2 = mysqli_prepare($con,
        "SELECT COUNT(*), MAX(login_time), COUNT(DISTINCT ip) FROM tbl_session_log WHERE email = ?"
    );
    mysqli_stmt_bind_param($s2, 's', $email);
    mysqli_stmt_execute($s2);
    mysqli_stmt_bind_result($s2, $tc, $ll, $ui);
    mysqli_stmt_fetch($s2);
    mysqli_stmt_close($s2);
    $data['total_logins'] = (int)$tc;
    $data['last_login']   = $ll;
    $data['unique_ips']   = (int)$ui;
}

$tla = mysqli_query($con, "SHOW TABLES LIKE 'tbl_login_attempts'");
if ($tla && mysqli_num_rows($tla) > 0) {
    $w   = date('Y-m-d H:i:s', strtotime('-7 days'));
    $s3  = mysqli_prepare($con,
        "SELECT COUNT(*) FROM tbl_login_attempts WHERE email = ? AND attempt_time >= ?"
    );
    mysqli_stmt_bind_param($s3, 'ss', $email, $w);
    mysqli_stmt_execute($s3);
    mysqli_stmt_bind_result($s3, $f7d);
    mysqli_stmt_fetch($s3);
    mysqli_stmt_close($s3);
    $data['failed_7d'] = (int)$f7d;
}

$tbc = mysqli_query($con, "SHOW TABLES LIKE 'tbl_backup_codes'");
if ($tbc && mysqli_num_rows($tbc) > 0) {
    $s4 = mysqli_prepare($con,
        "SELECT COUNT(*) FROM tbl_backup_codes WHERE email = ? AND used_at IS NULL"
    );
    mysqli_stmt_bind_param($s4, 's', $email);
    mysqli_stmt_execute($s4);
    mysqli_stmt_bind_result($s4, $bcr);
    mysqli_stmt_fetch($s4);
    mysqli_stmt_close($s4);
    $data['backup_codes_remaining'] = (int)$bcr;
}
mysqli_close($con);

// ── Ask Claude for a security report ────────────────────────────────────────
$reportText = '';
$error      = '';

$prompt = "Generate a concise security report for a user account with the following metrics:\n"
    . json_encode($data, JSON_PRETTY_PRINT)
    . "\n\nThe report should include:\n"
    . "1. An overall security score out of 100 (numeric)\n"
    . "2. A 2-3 sentence executive summary\n"
    . "3. Strengths (bullet list, up to 4 items)\n"
    . "4. Risks or weaknesses (bullet list, up to 4 items)\n"
    . "5. Prioritised recommendations (numbered list, up to 5 items)\n"
    . "Respond in clean plain text with clear section headings. Be specific and actionable.";

$payload  = json_encode([
    'model'      => ANTHROPIC_MODEL,
    'max_tokens' => 800,
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
$res  = curl_exec($ch);
$code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($res && $code === 200) {
    $decoded    = json_decode($res, true);
    $reportText = $decoded['content'][0]['text'] ?? '';
} else {
    $error = 'Could not generate report — AI service unavailable.';
}

// Format text as HTML (simple nl2br + bold headings)
function formatReport(string $text): string
{
    $text = htmlspecialchars($text);
    $text = preg_replace('/\*\*(.+?)\*\*/', '<strong>$1</strong>', $text);
    $text = nl2br($text);
    return $text;
}

$generatedAt = date('F j, Y \a\t g:i a');
?>
<!DOCTYPE html>
<html>
<head>
<title>Security Report &mdash; <?= htmlspecialchars($email) ?></title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" href="style/cleanup.css">
<style>
    h2 { color:#fff; text-align:center; margin-top:50px; text-transform:uppercase;
         font-size:1.3rem; letter-spacing:2px; }
    .sr-wrap { max-width:680px; margin:22px auto 60px; padding:0 16px; }
    .sr-header {
        background:linear-gradient(135deg,rgba(102,126,234,0.2),rgba(118,75,162,0.2));
        border:1px solid rgba(102,126,234,0.3); border-radius:16px;
        padding:22px 28px; margin-bottom:16px; color:#e0e0e0;
    }
    .sr-title { font-size:18px; font-weight:700; color:#fff; }
    .sr-sub   { font-size:12px; color:#64748b; margin-top:2px; }
    .sr-body  {
        background:rgba(255,255,255,0.07); border:1px solid rgba(255,255,255,0.12);
        border-radius:14px; padding:24px 28px; color:#d0d0d0;
        font-size:13px; line-height:1.8; white-space:pre-wrap;
    }
    .stats-row { display:flex; gap:10px; flex-wrap:wrap; margin:14px 0; }
    .s-box {
        background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.08);
        border-radius:10px; padding:10px 14px; flex:1; min-width:100px; text-align:center;
    }
    .s-val   { font-size:20px; font-weight:700; color:#fff; }
    .s-label { font-size:10px; color:#64748b; text-transform:uppercase; letter-spacing:1px; }
    .btn-print {
        background:rgba(255,255,255,0.08); border:1px solid rgba(255,255,255,0.15);
        border-radius:8px; color:#d0d0d0; padding:8px 18px;
        font-size:13px; cursor:pointer; transition:background .15s;
    }
    .btn-print:hover { background:rgba(255,255,255,0.15); }
    .back-link { text-align:center; margin-top:16px; }
    .back-link a { color:#a78bfa; font-size:13px; }
    @media print {
        body { background:#fff; color:#000; }
        .no-print { display:none; }
        .sr-body { background:#f9f9f9; color:#111; border:1px solid #ccc; }
        .sr-header { background:#eee; border:1px solid #ccc; color:#111; }
        .sr-title { color:#111; }
        .s-box { background:#eee; border:1px solid #ccc; }
        .s-val { color:#111; }
    }
</style>
</head>
<body>
<h2>&#x1F4CB; Security Report</h2>
<div class="sr-wrap">
    <div class="sr-header">
        <div class="sr-title">&#x1F916; AI Security Report</div>
        <div class="sr-sub">Generated for <?= htmlspecialchars($email) ?> &bull; <?= $generatedAt ?></div>

        <div class="stats-row">
            <div class="s-box">
                <div class="s-val"><?= (int)$data['total_logins'] ?></div>
                <div class="s-label">Logins</div>
            </div>
            <div class="s-box">
                <div class="s-val" style="color:<?= $data['failed_7d'] > 5 ? '#f87171' : '#4ade80' ?>">
                    <?= (int)$data['failed_7d'] ?>
                </div>
                <div class="s-label">Fails (7d)</div>
            </div>
            <div class="s-box">
                <div class="s-val"><?= (int)$data['unique_ips'] ?></div>
                <div class="s-label">Unique IPs</div>
            </div>
            <div class="s-box">
                <div class="s-val"><?= $data['totp_enabled'] ? '&#x2705;' : '&#x274C;' ?></div>
                <div class="s-label">2FA</div>
            </div>
            <div class="s-box">
                <div class="s-val"><?= (int)$data['backup_codes_remaining'] ?></div>
                <div class="s-label">Backups</div>
            </div>
        </div>

        <button class="btn-print no-print" onclick="window.print()">
            &#x1F5A8; Print / Save PDF
        </button>
    </div>

    <?php if ($error): ?>
    <div class="alert alert-warning py-2" style="font-size:13px"><?= htmlspecialchars($error) ?></div>
    <?php else: ?>
    <div class="sr-body"><?= formatReport($reportText) ?></div>
    <?php endif; ?>

    <div class="back-link no-print"><a href="homepage.php">&larr; Back to Dashboard</a></div>
</div>
</body>
</html>
