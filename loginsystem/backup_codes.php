<?php
require_once 'auth_check.php';
require_once 'utils.php';

$email   = $_SESSION['email'];
$con     = mysqli_connect('localhost', 'root', '', 'system');
$message = '';
$msgType = '';
$newCodes = [];   // shown once after generation

// Ensure tables exist
mysqli_query($con, "CREATE TABLE IF NOT EXISTS tbl_backup_codes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    code_hash VARCHAR(64) NOT NULL,
    used_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    INDEX idx_email (email)
)");

// Check 2FA
$totpEnabled = false;
$r = mysqli_query($con,
    "SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA='system' AND TABLE_NAME='tbl_signup' AND COLUMN_NAME='totp_enabled'"
);
if ($r && mysqli_num_rows($r) > 0) {
    $ts = mysqli_prepare($con, "SELECT totp_enabled FROM tbl_signup WHERE email = ?");
    mysqli_stmt_bind_param($ts, 's', $email);
    mysqli_stmt_execute($ts);
    mysqli_stmt_bind_result($ts, $te);
    mysqli_stmt_fetch($ts);
    mysqli_stmt_close($ts);
    $totpEnabled = (bool) $te;
}

// Handle generate / regenerate
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['generate']) && $totpEnabled) {
    // Delete old codes
    $del = mysqli_prepare($con, "DELETE FROM tbl_backup_codes WHERE email = ?");
    mysqli_stmt_bind_param($del, 's', $email);
    mysqli_stmt_execute($del);
    mysqli_stmt_close($del);

    // Generate 8 codes: format XXXX-XXXX-XXXX (12 hex chars per code)
    $now = date('Y-m-d H:i:s');
    for ($i = 0; $i < 8; $i++) {
        $raw  = bin2hex(random_bytes(6));                  // 12 hex chars
        $fmt  = strtoupper(substr($raw, 0, 4) . '-' . substr($raw, 4, 4) . '-' . substr($raw, 8, 4));
        $hash = hash('sha256', strtolower(str_replace('-', '', $raw)));
        $newCodes[] = $fmt;

        $ins = mysqli_prepare($con,
            "INSERT INTO tbl_backup_codes (email, code_hash, created_at) VALUES (?,?,?)"
        );
        mysqli_stmt_bind_param($ins, 'sss', $email, $hash, $now);
        mysqli_stmt_execute($ins);
        mysqli_stmt_close($ins);
    }

    log_audit($email, '2fa_backup_codes_generated', 'New backup codes generated',
              $_SERVER['REMOTE_ADDR'] ?? '', $con);
    $message = '8 new backup codes generated. Save them securely — they are shown only once!';
    $msgType = 'success';
}

// Fetch code stats
$usedCount  = 0;
$totalCount = 0;
$stmt = mysqli_prepare($con,
    "SELECT COUNT(*) total, SUM(used_at IS NOT NULL) used_cnt
     FROM tbl_backup_codes WHERE email = ?"
);
mysqli_stmt_bind_param($stmt, 's', $email);
mysqli_stmt_execute($stmt);
mysqli_stmt_bind_result($stmt, $totalCount, $usedCount);
mysqli_stmt_fetch($stmt);
mysqli_stmt_close($stmt);

$remaining = (int)$totalCount - (int)$usedCount;
mysqli_close($con);
?>
<!DOCTYPE html>
<html>
<head>
<title>2FA Backup Codes</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" href="style/cleanup.css">
<style>
    h2 { color:#fff; text-align:center; margin-top:56px; text-transform:uppercase;
         font-size:1.3rem; letter-spacing:2px; }
    .bc-wrap { max-width:520px; margin:22px auto 60px; padding:0 16px; }
    .bc-card {
        background:rgba(255,255,255,0.07); border:1px solid rgba(255,255,255,0.12);
        border-radius:16px; padding:26px 30px; color:#e0e0e0; margin-bottom:16px;
    }
    .card-label { font-size:11px; font-weight:700; letter-spacing:1.5px;
                  text-transform:uppercase; color:#60a5fa; margin-bottom:14px; }
    .stat-row { display:flex; gap:12px; margin-bottom:18px; }
    .stat-box {
        flex:1; background:rgba(255,255,255,0.05);
        border:1px solid rgba(255,255,255,0.08);
        border-radius:10px; padding:12px; text-align:center;
    }
    .stat-val   { font-size:24px; font-weight:700; }
    .stat-label { font-size:11px; color:#64748b; }
    .codes-grid {
        display:grid; grid-template-columns:repeat(2, 1fr); gap:8px;
        margin:16px 0;
    }
    .code-pill {
        background:rgba(167,139,250,0.12); border:1px solid rgba(167,139,250,0.25);
        border-radius:8px; padding:8px 12px;
        font-family:monospace; font-size:15px; font-weight:700;
        color:#c4b5fd; text-align:center; letter-spacing:2px;
    }
    .btn-gen {
        width:100%; background:linear-gradient(135deg,#667eea,#764ba2);
        border:none; border-radius:8px; color:#fff;
        padding:10px; font-size:14px; cursor:pointer; transition:opacity .2s;
    }
    .btn-gen:hover { opacity:0.85; }
    .btn-print {
        width:100%; background:rgba(255,255,255,0.07);
        border:1px solid rgba(255,255,255,0.15); border-radius:8px; color:#d0d0d0;
        padding:8px; font-size:13px; cursor:pointer; margin-top:8px; transition:background .15s;
    }
    .btn-print:hover { background:rgba(255,255,255,0.12); }
    .warn-box {
        background:rgba(251,146,60,0.1); border:1px solid rgba(251,146,60,0.3);
        border-radius:10px; padding:12px; font-size:12px; color:#fdba74; line-height:1.6;
        margin-bottom:16px;
    }
    .back-link { text-align:center; margin-top:16px; }
    .back-link a { color:#a78bfa; font-size:13px; }
    @media print {
        body { background:#fff; color:#000; }
        .no-print { display:none; }
        .code-pill { background:#eee; color:#000; border:1px solid #ccc; }
    }
</style>
</head>
<body>
<h2>&#x1F5DD; 2FA Backup Codes</h2>
<div class="bc-wrap">
    <?php if (!$totpEnabled): ?>
    <div class="bc-card">
        <div class="warn-box">
            &#x26A0; Two-factor authentication is not enabled on your account.
            Backup codes are only available when 2FA is active.
        </div>
        <a href="totp_setup.php" style="color:#a78bfa;font-size:13px">
            &#x2192; Enable 2FA first
        </a>
    </div>

    <?php else: ?>
    <?php if ($message): ?>
    <div class="alert alert-<?= $msgType ?> py-2 mb-3" style="font-size:13px">
        <?= htmlspecialchars($message) ?>
    </div>
    <?php endif; ?>

    <?php if (!empty($newCodes)): ?>
    <!-- Show codes once after generation -->
    <div class="bc-card">
        <div class="card-label">&#x1F4CB; Your backup codes — save these now!</div>
        <div class="warn-box">
            These codes are shown <strong>only once</strong>. Store them in a safe place.
            Each code can be used once instead of your 2FA app.
        </div>
        <div class="codes-grid">
            <?php foreach ($newCodes as $code): ?>
            <div class="code-pill"><?= htmlspecialchars($code) ?></div>
            <?php endforeach; ?>
        </div>
        <button class="btn-print no-print" onclick="window.print()">
            &#x1F5A8; Print / Save as PDF
        </button>
    </div>
    <?php endif; ?>

    <!-- Status card -->
    <div class="bc-card no-print">
        <div class="card-label">&#x1F4CA; Code Status</div>
        <div class="stat-row">
            <div class="stat-box">
                <div class="stat-val" style="color:<?= $remaining > 2 ? '#4ade80' : '#f87171' ?>">
                    <?= (int)$remaining ?>
                </div>
                <div class="stat-label">Remaining</div>
            </div>
            <div class="stat-box">
                <div class="stat-val" style="color:#94a3b8"><?= (int)$usedCount ?></div>
                <div class="stat-label">Used</div>
            </div>
            <div class="stat-box">
                <div class="stat-val" style="color:#c4b5fd"><?= (int)$totalCount ?></div>
                <div class="stat-label">Total</div>
            </div>
        </div>

        <?php if ($remaining < 3 && $totalCount > 0): ?>
        <div class="warn-box">
            &#x26A0; You're running low on backup codes. Regenerate them soon.
        </div>
        <?php endif; ?>

        <form method="post"
              onsubmit="return confirm('This will invalidate all existing backup codes. Continue?')">
            <input type="hidden" name="generate" value="1">
            <button type="submit" class="btn-gen">
                <?= $totalCount > 0 ? '&#x1F504; Regenerate Backup Codes' : '&#x2728; Generate Backup Codes' ?>
            </button>
        </form>
    </div>
    <?php endif; ?>

    <div class="back-link no-print"><a href="totp_setup.php">&larr; Back to 2FA Setup</a></div>
</div>
</body>
</html>
