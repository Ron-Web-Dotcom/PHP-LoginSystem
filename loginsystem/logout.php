<?php
session_start();
require_once 'api_config.php';

// Capture username before the session is gone
$user = isset($_SESSION['email'])
      ? htmlspecialchars(explode('@', $_SESSION['email'])[0])
      : 'friend';

// Generate AI farewell server-side
$prompt = "Write a warm, friendly logout message for a user named '{$user}'. "
        . "Include one short security reminder (e.g. lock your screen, close the browser). "
        . "Under 28 words total. No quotation marks.";

$payload = [
    'model'      => ANTHROPIC_MODEL,
    'max_tokens' => 60,
    'messages'   => [['role' => 'user', 'content' => $prompt]]
];

$farewell = "Goodbye, {$user}! Stay safe and remember to lock your screen.";

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
curl_close($ch);

$result = json_decode($response, true);
if (!empty($result['content'][0]['text'])) {
    $farewell = htmlspecialchars(trim($result['content'][0]['text']));
}

// ── Invalidate remember-me token before destroying the session ────────────────
if (!empty($_COOKIE['remember_token'])) {
    $sep = strpos($_COOKIE['remember_token'], ':');
    if ($sep !== false) {
        $rawToken  = substr($_COOKIE['remember_token'], $sep + 1);
        $tokenHash = hash('sha256', $rawToken);
        $logoutCon = mysqli_connect('localhost', 'root', '', 'system');
        if ($logoutCon) {
            $tblRt = mysqli_query($logoutCon, "SHOW TABLES LIKE 'tbl_remember_tokens'");
            if ($tblRt && mysqli_num_rows($tblRt) > 0) {
                $delRt = mysqli_prepare($logoutCon, "DELETE FROM tbl_remember_tokens WHERE token_hash = ?");
                if ($delRt) {
                    mysqli_stmt_bind_param($delRt, 's', $tokenHash);
                    mysqli_stmt_execute($delRt);
                    mysqli_stmt_close($delRt);
                }
            }
            mysqli_close($logoutCon);
        }
    }
    setcookie('remember_token', '', time() - 3600, '/', '', false, true);
}

session_destroy();
?>
<!DOCTYPE html>
<html>
<head>
<title>Logged Out</title>
<link rel="stylesheet" type="text/css" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" type="text/css" href="style/cleanup.css">
<style>
    h1 { color:#fff; text-align:center; margin-top:180px; text-transform:uppercase; }
    .farewell-card {
        max-width:440px; margin:22px auto 0;
        background:rgba(255,255,255,0.08);
        border:1px solid rgba(255,255,255,0.15);
        border-radius:14px; padding:22px 28px;
        text-align:center; backdrop-filter:blur(6px);
    }
    .farewell-card .wave { font-size:32px; margin-bottom:10px; }
    .farewell-card p { color:#e0e0e0; font-size:14px; line-height:1.7; margin:0 0 16px; }
    .farewell-card a {
        display:inline-block; padding:8px 22px;
        background:linear-gradient(135deg,#667eea,#764ba2);
        color:#fff; border-radius:8px; font-size:13px;
        text-decoration:none; transition:opacity .2s;
    }
    .farewell-card a:hover { opacity:0.85; color:#fff; }
    .countdown { color:#666; font-size:12px; margin-top:12px; margin-bottom:0; }
</style>
</head>
<body>
<h1>&#x1F44B; See you, <?php echo $user; ?>!</h1>

<div class="farewell-card">
    <div class="wave">&#x1F512;</div>
    <p><?php echo $farewell; ?></p>
    <a href="login.php">Sign in again</a>
    <p class="countdown">Redirecting in <span id="n">5</span>s&hellip;</p>
</div>

<script>
let t = 5;
const el = document.getElementById('n');
const iv = setInterval(() => {
    el.textContent = --t;
    if (t <= 0) { clearInterval(iv); window.location.href = 'login.php'; }
}, 1000);
</script>
</body>
</html>
