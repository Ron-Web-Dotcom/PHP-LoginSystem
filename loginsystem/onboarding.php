<?php
require_once 'auth_check.php';

$email = $_SESSION['email'];
$con   = mysqli_connect('localhost', 'root', '', 'system');

// Ensure columns exist
$addCols = ['onboarded TINYINT(1) DEFAULT 0', 'totp_enabled TINYINT(1) DEFAULT 0'];
foreach ($addCols as $def) {
    $col = explode(' ', $def)[0];
    $r   = mysqli_query($con,
        "SELECT 1 FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA='system' AND TABLE_NAME='tbl_signup' AND COLUMN_NAME='{$col}'"
    );
    if ($r && mysqli_num_rows($r) === 0) {
        mysqli_query($con, "ALTER TABLE tbl_signup ADD COLUMN {$def}");
    }
}

// Handle "mark complete" action
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['complete'])) {
    $upd = mysqli_prepare($con, "UPDATE tbl_signup SET onboarded = 1 WHERE email = ?");
    mysqli_stmt_bind_param($upd, 's', $email);
    mysqli_stmt_execute($upd);
    mysqli_stmt_close($upd);
    header('location:homepage.php');
    exit();
}

// Fetch state
$totpEnabled = false;
$onboarded   = false;
$stmt = mysqli_prepare($con, "SELECT totp_enabled, onboarded FROM tbl_signup WHERE email = ?");
mysqli_stmt_bind_param($stmt, 's', $email);
mysqli_stmt_execute($stmt);
mysqli_stmt_bind_result($stmt, $te, $ob);
mysqli_stmt_fetch($stmt);
mysqli_stmt_close($stmt);
$totpEnabled = (bool) $te;
$onboarded   = (bool) $ob;

// Backup codes generated?
$backupCodesOk = false;
$tbl2 = mysqli_query($con, "SHOW TABLES LIKE 'tbl_backup_codes'");
if ($tbl2 && mysqli_num_rows($tbl2) > 0) {
    $bs = mysqli_prepare($con,
        "SELECT COUNT(*) FROM tbl_backup_codes WHERE email = ? AND used_at IS NULL"
    );
    mysqli_stmt_bind_param($bs, 's', $email);
    mysqli_stmt_execute($bs);
    mysqli_stmt_bind_result($bs, $bCount);
    mysqli_stmt_fetch($bs);
    mysqli_stmt_close($bs);
    $backupCodesOk = $bCount > 0;
}

// Audit log started?
$auditStarted = false;
$tbl3 = mysqli_query($con, "SHOW TABLES LIKE 'tbl_audit_log'");
if ($tbl3 && mysqli_num_rows($tbl3) > 0) {
    $as = mysqli_prepare($con, "SELECT 1 FROM tbl_audit_log WHERE email = ? LIMIT 1");
    mysqli_stmt_bind_param($as, 's', $email);
    mysqli_stmt_execute($as);
    mysqli_stmt_store_result($as);
    $auditStarted = mysqli_stmt_num_rows($as) > 0;
    mysqli_stmt_close($as);
}

mysqli_close($con);

$steps = [
    ['label' => 'Account created',          'done' => true,          'link' => null,                   'icon' => '&#x1F195;'],
    ['label' => 'Enable Two-Factor Auth',    'done' => $totpEnabled,  'link' => 'totp_setup.php',       'icon' => '&#x1F510;'],
    ['label' => 'Generate backup codes',     'done' => $backupCodesOk,'link' => 'backup_codes.php',     'icon' => '&#x1F5DD;'],
    ['label' => 'Review your audit log',     'done' => $auditStarted, 'link' => 'audit_log.php',        'icon' => '&#x1F4DC;'],
    ['label' => 'Set a strong password',     'done' => false,         'link' => 'change_password.php',  'icon' => '&#x1F511;'],
    ['label' => 'Review active sessions',    'done' => false,         'link' => 'session_manager.php',  'icon' => '&#x1F5A5;'],
];

$total = count($steps);
$done  = array_sum(array_column($steps, 'done'));
$pct   = (int) round($done / $total * 100);
$allOk = $done === $total;
?>
<!DOCTYPE html>
<html>
<head>
<title>Security Setup</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" href="style/cleanup.css">
<style>
    h2 { color:#fff; text-align:center; margin-top:56px; text-transform:uppercase;
         font-size:1.3rem; letter-spacing:2px; }
    .ob-wrap { max-width:520px; margin:22px auto 60px; padding:0 16px; }
    .ob-card {
        background:rgba(255,255,255,0.07); border:1px solid rgba(255,255,255,0.12);
        border-radius:16px; padding:24px 28px; color:#e0e0e0;
    }
    .ob-title { font-size:15px; font-weight:700; color:#fff; margin-bottom:4px; }
    .ob-sub   { font-size:12px; color:#64748b; margin-bottom:18px; }
    .progress { height:8px; border-radius:4px; background:rgba(255,255,255,0.08); margin-bottom:20px; }
    .progress-bar { border-radius:4px; transition:width .5s ease; }
    .step-row {
        display:flex; align-items:center; gap:12px;
        padding:10px 0; border-bottom:1px solid rgba(255,255,255,0.06);
    }
    .step-row:last-child { border-bottom:none; }
    .step-icon { font-size:20px; width:28px; text-align:center; flex-shrink:0; }
    .step-label { flex:1; font-size:13px; color:#d0d0d0; }
    .step-done  { color:#4ade80; }
    .step-check { font-size:16px; }
    .step-link  {
        font-size:11px; font-weight:600; color:#a78bfa;
        text-decoration:none; border:1px solid rgba(167,139,250,0.3);
        border-radius:6px; padding:3px 10px; white-space:nowrap;
    }
    .step-link:hover { background:rgba(167,139,250,0.1); text-decoration:none; }
    .btn-complete {
        width:100%; background:linear-gradient(135deg,#4ade80,#16a34a);
        border:none; border-radius:8px; color:#fff;
        padding:10px; font-size:14px; cursor:pointer; margin-top:16px;
        transition:opacity .2s;
    }
    .btn-complete:hover { opacity:0.85; }
    .pct-label { text-align:right; font-size:11px; color:#64748b; margin-bottom:4px; }
    .back-link { text-align:center; margin-top:16px; }
    .back-link a { color:#a78bfa; font-size:13px; }
</style>
</head>
<body>
<h2>&#x1F6E1; Security Setup</h2>
<div class="ob-wrap">
    <div class="ob-card">
        <div class="ob-title">Your security checklist</div>
        <div class="ob-sub">Complete these steps to secure your account</div>

        <div class="pct-label"><?= $done ?>/<?= $total ?> complete &mdash; <?= $pct ?>%</div>
        <div class="progress">
            <div class="progress-bar <?= $pct >= 100 ? 'bg-success' : 'bg-primary' ?>"
                 style="width:<?= $pct ?>%"></div>
        </div>

        <?php foreach ($steps as $s): ?>
        <div class="step-row">
            <div class="step-icon"><?= $s['icon'] ?></div>
            <div class="step-label <?= $s['done'] ? 'step-done' : '' ?>">
                <?= $s['label'] ?>
            </div>
            <div class="step-check">
                <?php if ($s['done']): ?>
                <span style="color:#4ade80">&#x2705;</span>
                <?php elseif ($s['link']): ?>
                <a href="<?= htmlspecialchars($s['link']) ?>" class="step-link">Set up &rarr;</a>
                <?php else: ?>
                <span style="color:#475569">&#x25CB;</span>
                <?php endif; ?>
            </div>
        </div>
        <?php endforeach; ?>

        <?php if ($allOk): ?>
        <form method="post">
            <input type="hidden" name="complete" value="1">
            <button type="submit" class="btn-complete">&#x1F389; All done — go to Dashboard</button>
        </form>
        <?php endif; ?>
    </div>

    <?php if ($onboarded): ?>
    <p style="color:#64748b;font-size:12px;text-align:center;margin-top:10px">
        You completed onboarding. You can revisit this checklist any time.
    </p>
    <?php endif; ?>

    <div class="back-link"><a href="homepage.php">&larr; Back to Dashboard</a></div>
</div>
</body>
</html>
