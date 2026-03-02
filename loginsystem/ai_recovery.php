<?php
/**
 * AI-Assisted Account Recovery — passwordless identity verification via Claude.
 *
 * ⚠ DEMO ONLY — not suitable for production without additional safeguards.
 *
 * Flow:
 *   Step 1 → Enter email
 *   Step 2 → Claude asks 3 personalised questions based on account metadata
 *   Step 3 → User answers all 3
 *   Step 4 → Claude evaluates; if satisfied, generates a one-time magic login link
 */
session_start();
require_once 'api_config.php';

$step    = (int) ($_POST['step'] ?? $_GET['step'] ?? 1);
$email   = trim($_POST['email'] ?? $_SESSION['recovery_email'] ?? '');
$error   = '';
$questions  = [];
$magicLink  = '';
$aiVerdict  = '';

// ── Helper: call Claude ───────────────────────────────────────────────────────
function ask_claude(string $prompt): string
{
    $payload = json_encode([
        'model'      => ANTHROPIC_MODEL,
        'max_tokens' => 600,
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
    $res  = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if (!$res || $code !== 200) return '';
    $d = json_decode($res, true);
    return $d['content'][0]['text'] ?? '';
}

// ── Step 1: Email submitted ───────────────────────────────────────────────────
if ($step === 2 && $email !== '') {
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Invalid email address.';
        $step  = 1;
    } else {
        $con   = mysqli_connect('localhost', 'root', '', 'system');
        $check = mysqli_prepare($con, "SELECT email FROM tbl_signup WHERE email = ?");
        mysqli_stmt_bind_param($check, 's', $email);
        mysqli_stmt_execute($check);
        mysqli_stmt_store_result($check);
        $exists = mysqli_stmt_num_rows($check) > 0;
        mysqli_stmt_close($check);

        // Gather account metadata (no PII)
        $meta = [];
        if ($exists) {
            // Total login count
            $tsl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_session_log'");
            if ($tsl && mysqli_num_rows($tsl) > 0) {
                $s = mysqli_prepare($con, "SELECT COUNT(*), MIN(login_time) FROM tbl_session_log WHERE email = ?");
                mysqli_stmt_bind_param($s, 's', $email);
                mysqli_stmt_execute($s);
                mysqli_stmt_bind_result($s, $tc, $fl);
                mysqli_stmt_fetch($s);
                mysqli_stmt_close($s);
                $meta['total_logins']      = (int)$tc;
                $meta['first_login_month'] = $fl ? date('F Y', strtotime($fl)) : 'unknown';
            }
            // 2FA enabled?
            $ts2 = mysqli_prepare($con, "SELECT totp_enabled FROM tbl_signup WHERE email = ?");
            mysqli_stmt_bind_param($ts2, 's', $email);
            mysqli_stmt_execute($ts2);
            mysqli_stmt_bind_result($ts2, $te);
            mysqli_stmt_fetch($ts2);
            mysqli_stmt_close($ts2);
            $meta['totp_enabled'] = (bool)$te;
        }
        mysqli_close($con);

        if (!$exists) {
            // Proceed anyway to avoid email enumeration, but use empty meta
            $meta = ['total_logins' => 0, 'first_login_month' => 'unknown', 'totp_enabled' => false];
        }

        $_SESSION['recovery_email'] = $email;
        $_SESSION['recovery_meta']  = $meta;

        // Ask Claude to formulate 3 questions
        $qPrompt = "You are a security assistant helping verify a user's identity for account recovery.\n"
            . "Account metadata (not the user's actual responses yet): " . json_encode($meta) . "\n\n"
            . "Generate exactly 3 short, clear identity-verification questions that can be answered from memory.\n"
            . "The questions should be based on typical account activity hints from the metadata.\n"
            . "Respond with ONLY a JSON array of 3 strings, e.g.:\n"
            . "[\"Question one?\", \"Question two?\", \"Question three?\"]";

        $raw = ask_claude($qPrompt);
        $raw = preg_replace('/^```(?:json)?\s*/m', '', $raw);
        $raw = preg_replace('/```\s*$/m', '', $raw);
        $questions = json_decode(trim($raw), true);
        if (!is_array($questions) || count($questions) < 3) {
            $questions = [
                'Approximately how many times have you logged into this account?',
                'In what month and year did you first use this account?',
                'Does your account have two-factor authentication enabled?',
            ];
        }
        $questions = array_slice($questions, 0, 3);
        $_SESSION['recovery_questions'] = $questions;
        $step = 2;
    }
} elseif ($step === 3) {
    // ── Step 3: Evaluate answers ──────────────────────────────────────────────
    $email     = $_SESSION['recovery_email']   ?? '';
    $qs        = $_SESSION['recovery_questions']?? [];
    $meta      = $_SESSION['recovery_meta']    ?? [];
    $answers   = [
        trim($_POST['a1'] ?? ''),
        trim($_POST['a2'] ?? ''),
        trim($_POST['a3'] ?? ''),
    ];

    $evalPrompt = "You are a security assistant performing account recovery identity verification.\n"
        . "Account metadata: " . json_encode($meta) . "\n\n"
        . "Questions asked and user's answers:\n";
    for ($i = 0; $i < 3; $i++) {
        $evalPrompt .= "Q" . ($i+1) . ": " . ($qs[$i] ?? '') . "\n"
                     . "A" . ($i+1) . ": " . $answers[$i] . "\n\n";
    }
    $evalPrompt .= "Based on the answers vs. metadata, determine if the user is likely the account owner.\n"
        . "Respond with a JSON object: { \"verified\": true|false, \"confidence\": \"high|medium|low\", \"reason\": \"...\" }\n"
        . "ONLY valid JSON, no markdown.";

    $raw = ask_claude($evalPrompt);
    $raw = preg_replace('/^```(?:json)?\s*/m', '', $raw);
    $raw = preg_replace('/```\s*$/m', '', $raw);
    $verdict = json_decode(trim($raw), true);

    if (!$verdict) $verdict = ['verified' => false, 'confidence' => 'low', 'reason' => 'Could not evaluate.'];
    $aiVerdict = $verdict;

    if (!empty($verdict['verified']) && $verdict['confidence'] !== 'low') {
        // Generate magic link
        $con      = mysqli_connect('localhost', 'root', '', 'system');
        mysqli_query($con, "CREATE TABLE IF NOT EXISTS tbl_magic_links (
            id INT AUTO_INCREMENT PRIMARY KEY, email VARCHAR(255) NOT NULL,
            token_hash VARCHAR(64) NOT NULL, expires_at DATETIME NOT NULL,
            used TINYINT(1) DEFAULT 0, INDEX idx_token (token_hash)
        )");
        $rawToken  = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $rawToken);
        $expires   = date('Y-m-d H:i:s', time() + 900);
        $ins = mysqli_prepare($con,
            "INSERT INTO tbl_magic_links (email, token_hash, expires_at, used) VALUES (?,?,?,0)"
        );
        mysqli_stmt_bind_param($ins, 'sss', $email, $tokenHash, $expires);
        mysqli_stmt_execute($ins);
        mysqli_stmt_close($ins);
        mysqli_close($con);

        $base      = (isset($_SERVER['HTTPS']) ? 'https' : 'http')
                   . '://' . $_SERVER['HTTP_HOST']
                   . rtrim(dirname($_SERVER['PHP_SELF']), '/\\');
        $magicLink = $base . '/magic_auth.php?token=' . urlencode($rawToken);
    }
    $step = 3;
}
?>
<!DOCTYPE html>
<html>
<head>
<title>AI Account Recovery</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" href="style/cleanup.css">
<style>
    h2 { color:#fff; text-align:center; margin-top:60px; text-transform:uppercase;
         font-size:1.3rem; letter-spacing:2px; }
    .rc-card {
        max-width:480px; margin:26px auto 60px;
        background:rgba(255,255,255,0.07); border:1px solid rgba(255,255,255,0.13);
        border-radius:16px; padding:28px 32px; backdrop-filter:blur(8px);
    }
    .rc-card label { color:#d0d0d0; font-size:13px; }
    .rc-card .form-control {
        background:rgba(255,255,255,0.07); border:1px solid rgba(255,255,255,0.18);
        color:#fff; border-radius:8px;
    }
    .rc-card .form-control:focus {
        background:rgba(255,255,255,0.1); color:#fff;
        box-shadow:none; border-color:#667eea;
    }
    .rc-card .form-control::placeholder { color:#555; }
    .btn-primary-custom {
        width:100%; background:linear-gradient(135deg,#667eea,#764ba2);
        border:none; border-radius:8px; color:#fff;
        padding:10px; font-size:14px; cursor:pointer; transition:opacity .2s;
    }
    .btn-primary-custom:hover { opacity:0.85; }
    .demo-warn {
        background:rgba(251,146,60,0.12); border:1px solid rgba(251,146,60,0.3);
        border-radius:10px; padding:12px; font-size:12px; color:#fdba74;
        line-height:1.6; margin-bottom:18px;
    }
    .q-box {
        background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.09);
        border-radius:10px; padding:12px 14px; margin-bottom:12px;
    }
    .q-text { font-size:13px; color:#d0d0d0; margin-bottom:6px; }
    .verdict-box {
        border-radius:12px; padding:16px; margin-bottom:16px; font-size:13px;
    }
    .verdict-ok  { background:rgba(34,197,94,0.12); border:1px solid rgba(34,197,94,0.3); color:#86efac; }
    .verdict-fail{ background:rgba(239,68,68,0.12); border:1px solid rgba(239,68,68,0.3); color:#fca5a5; }
    .magic-box {
        background:rgba(102,126,234,0.1); border:1px solid rgba(102,126,234,0.3);
        border-radius:10px; padding:12px; margin-top:14px;
        word-break:break-all; font-family:monospace; font-size:11px; color:#a78bfa;
    }
    .back-link { text-align:center; margin-top:16px; }
    .back-link a { color:#a78bfa; font-size:13px; }
</style>
</head>
<body>
<h2>&#x1F916; AI Account Recovery</h2>
<div class="rc-card">
    <div class="demo-warn">
        &#x26A0; <strong>Demo only.</strong> This feature is for demonstration purposes.
        In production, AI-based identity verification must be combined with additional
        proof-of-identity mechanisms.
    </div>

    <?php if ($step === 1 || $error): ?>
    <!-- Step 1: Enter email -->
    <?php if ($error): ?>
    <div class="alert alert-danger py-2 mb-3" style="font-size:13px"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <p style="color:#94a3b8;font-size:13px">
        Forgot your password and can't access your email?
        Claude will ask you a few questions to verify your identity.
    </p>
    <form method="post">
        <input type="hidden" name="step" value="2">
        <div class="form-group">
            <label>Account email address</label>
            <input type="email" name="email" class="form-control"
                   placeholder="you@example.com" required>
        </div>
        <button type="submit" class="btn-primary-custom">&#x1F916; Start Verification</button>
    </form>

    <?php elseif ($step === 2 && !empty($questions)): ?>
    <!-- Step 2: Answer questions -->
    <p style="color:#94a3b8;font-size:13px;margin-bottom:14px">
        Please answer the following questions to verify your identity for
        <strong style="color:#c4b5fd"><?= htmlspecialchars($email) ?></strong>:
    </p>
    <form method="post">
        <input type="hidden" name="step"  value="3">
        <input type="hidden" name="email" value="<?= htmlspecialchars($email) ?>">
        <?php foreach ($questions as $i => $q): ?>
        <div class="q-box">
            <div class="q-text"><?= htmlspecialchars($q) ?></div>
            <input type="text" name="a<?= $i+1 ?>" class="form-control"
                   placeholder="Your answer" required>
        </div>
        <?php endforeach; ?>
        <button type="submit" class="btn-primary-custom" style="margin-top:8px">
            &#x1F50D; Verify My Identity
        </button>
    </form>

    <?php elseif ($step === 3): ?>
    <!-- Step 3: Verdict -->
    <?php if (!empty($aiVerdict['verified']) && $aiVerdict['confidence'] !== 'low'): ?>
    <div class="verdict-box verdict-ok">
        <strong>&#x2705; Identity Verified</strong><br>
        Confidence: <strong><?= htmlspecialchars($aiVerdict['confidence']) ?></strong><br>
        <?= htmlspecialchars($aiVerdict['reason'] ?? '') ?>
    </div>
    <?php if ($magicLink): ?>
    <p style="font-size:13px;color:#d0d0d0">Your one-time login link (valid 15 min):</p>
    <div class="magic-box">
        <div id="ml-url"><?= htmlspecialchars($magicLink) ?></div>
        <button style="margin-top:6px;background:rgba(102,126,234,0.2);border:1px solid rgba(102,126,234,0.3);color:#a78bfa;border-radius:6px;padding:3px 10px;font-size:11px;cursor:pointer"
                onclick="navigator.clipboard.writeText(document.getElementById('ml-url').textContent);this.textContent='Copied!'">
            Copy link
        </button>
    </div>
    <p style="font-size:11px;color:#64748b;margin-top:8px">After login, change your password immediately.</p>
    <?php endif; ?>
    <?php else: ?>
    <div class="verdict-box verdict-fail">
        <strong>&#x274C; Verification Failed</strong><br>
        <?= htmlspecialchars($aiVerdict['reason'] ?? 'Could not verify identity.') ?>
    </div>
    <p style="font-size:13px;color:#94a3b8">
        Please contact support or try the standard password reset.
    </p>
    <?php endif; ?>
    <?php endif; ?>

    <div class="back-link"><a href="login.php">&larr; Back to Login</a></div>
</div>
</body>
</html>
