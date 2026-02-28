<?php
require_once 'auth_check.php';

$email = $_SESSION['email'];
$con   = mysqli_connect('localhost', 'root', '', 'system');

// Ensure totp_enabled column exists
$r = mysqli_query($con,
    "SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA='system' AND TABLE_NAME='tbl_signup' AND COLUMN_NAME='totp_enabled'"
);
if ($r && mysqli_num_rows($r) === 0) {
    mysqli_query($con, "ALTER TABLE tbl_signup ADD COLUMN totp_enabled TINYINT(1) DEFAULT 0");
}

// Fetch 2FA status
$totpEnabled = false;
$stmt = mysqli_prepare($con, "SELECT totp_enabled FROM tbl_signup WHERE email = ?");
mysqli_stmt_bind_param($stmt, 's', $email);
mysqli_stmt_execute($stmt);
mysqli_stmt_bind_result($stmt, $te);
mysqli_stmt_fetch($stmt);
mysqli_stmt_close($stmt);
$totpEnabled = (bool) $te;

// Session stats
$totalSessions = 0;
$lastLoginTime = null;
$lastLoginIp   = null;
$tcheck = mysqli_query($con, "SHOW TABLES LIKE 'tbl_session_log'");
if ($tcheck && mysqli_num_rows($tcheck) > 0) {
    $s = mysqli_prepare($con,
        "SELECT COUNT(*), MAX(login_time) FROM tbl_session_log WHERE email = ?"
    );
    mysqli_stmt_bind_param($s, 's', $email);
    mysqli_stmt_execute($s);
    mysqli_stmt_bind_result($s, $totalSessions, $lastLoginTime);
    mysqli_stmt_fetch($s);
    mysqli_stmt_close($s);

    // Last IP
    $s2 = mysqli_prepare($con,
        "SELECT ip FROM tbl_session_log WHERE email = ? ORDER BY login_time DESC LIMIT 1"
    );
    mysqli_stmt_bind_param($s2, 's', $email);
    mysqli_stmt_execute($s2);
    mysqli_stmt_bind_result($s2, $lastLoginIp);
    mysqli_stmt_fetch($s2);
    mysqli_stmt_close($s2);
}

// Failed attempts (last 7 days)
$failedRecent = 0;
$tcheck2 = mysqli_query($con, "SHOW TABLES LIKE 'tbl_login_attempts'");
if ($tcheck2 && mysqli_num_rows($tcheck2) > 0) {
    $w = date('Y-m-d H:i:s', strtotime('-7 days'));
    $s3 = mysqli_prepare($con,
        "SELECT COUNT(*) FROM tbl_login_attempts WHERE email = ? AND attempt_time >= ?"
    );
    mysqli_stmt_bind_param($s3, 'ss', $email, $w);
    mysqli_stmt_execute($s3);
    mysqli_stmt_bind_result($s3, $failedRecent);
    mysqli_stmt_fetch($s3);
    mysqli_stmt_close($s3);
}

// Recent 5 logins
$recentLogins = [];
if ($tcheck && mysqli_num_rows($tcheck) > 0) {
    $s4 = mysqli_prepare($con,
        "SELECT login_time, ip FROM tbl_session_log WHERE email = ? ORDER BY login_time DESC LIMIT 5"
    );
    mysqli_stmt_bind_param($s4, 's', $email);
    mysqli_stmt_execute($s4);
    $r4 = mysqli_stmt_get_result($s4);
    while ($row = mysqli_fetch_assoc($r4)) { $recentLogins[] = $row; }
    mysqli_stmt_close($s4);
}

mysqli_close($con);

$displayName = explode('@', $email)[0];
?>
<!DOCTYPE html>
<html>
<head>
<title>My Profile</title>
<link rel="stylesheet" type="text/css" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" type="text/css" href="style/cleanup.css">
<style>
    h2 { color:#fff; text-align:center; margin-top:56px; text-transform:uppercase;
         font-size:1.3rem; letter-spacing:2px; }
    .profile-card {
        max-width:500px; margin:22px auto 0;
        background:rgba(255,255,255,0.07);
        border:1px solid rgba(255,255,255,0.13);
        border-radius:16px; padding:28px 32px;
        backdrop-filter:blur(8px); color:#e0e0e0;
    }
    .avatar {
        width:68px; height:68px; border-radius:50%;
        background:linear-gradient(135deg,#667eea,#764ba2);
        display:flex; align-items:center; justify-content:center;
        font-size:28px; font-weight:700; color:#fff;
        margin:0 auto 14px;
    }
    .profile-email { text-align:center; color:#94a3b8; font-size:13px; margin-bottom:20px; }
    .profile-name  { text-align:center; font-size:18px; font-weight:700; color:#fff; }
    .stats-row { display:flex; gap:12px; margin-bottom:20px; }
    .stat-box {
        flex:1; background:rgba(255,255,255,0.05);
        border:1px solid rgba(255,255,255,0.08);
        border-radius:10px; padding:12px; text-align:center;
    }
    .stat-val   { font-size:22px; font-weight:700; color:#fff; }
    .stat-label { font-size:11px; color:#64748b; margin-top:2px; }
    .section-label {
        font-size:11px; font-weight:700; letter-spacing:1.2px;
        text-transform:uppercase; color:#60a5fa; margin:16px 0 8px;
    }
    .badge-2fa {
        display:inline-block; padding:3px 10px; border-radius:20px;
        font-size:12px; font-weight:600;
    }
    .badge-on  { background:rgba(34,197,94,0.2);  color:#86efac; border:1px solid rgba(34,197,94,0.35); }
    .badge-off { background:rgba(148,163,184,0.2); color:#94a3b8; border:1px solid rgba(148,163,184,0.3); }
    .link-btn {
        display:block; width:100%; text-align:left;
        background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.09);
        border-radius:8px; padding:10px 14px; color:#d0d0d0; font-size:13px;
        text-decoration:none; margin-bottom:8px; transition:background .15s;
    }
    .link-btn:hover { background:rgba(255,255,255,0.1); color:#fff; text-decoration:none; }
    .login-mini-table { width:100%; border-collapse:collapse; font-size:12px; }
    .login-mini-table td { padding:5px 4px; border-bottom:1px solid rgba(255,255,255,0.06); }
    .login-mini-table tr:last-child td { border-bottom:none; }
    .lmt-time { color:#94a3b8; }
    .lmt-ip   { color:#64748b; font-family:monospace; text-align:right; }
    .failed-warn { color:#f97316; font-size:12px; margin-top:4px; }
    .back-link { text-align:center; margin-top:18px; }
    .back-link a { color:#a78bfa; font-size:13px; }
</style>
</head>
<body>
<h2>&#x1F464; My Profile</h2>

<div class="profile-card">
    <div class="avatar"><?php echo strtoupper(substr($displayName, 0, 1)); ?></div>
    <div class="profile-name"><?php echo htmlspecialchars($displayName); ?></div>
    <div class="profile-email"><?php echo htmlspecialchars($email); ?></div>

    <!-- Stats -->
    <div class="stats-row">
        <div class="stat-box">
            <div class="stat-val"><?php echo (int) $totalSessions; ?></div>
            <div class="stat-label">Total Logins</div>
        </div>
        <div class="stat-box">
            <div class="stat-val" style="color:<?php echo $failedRecent > 0 ? '#f97316' : '#86efac'; ?>">
                <?php echo (int) $failedRecent; ?>
            </div>
            <div class="stat-label">Failed (7 days)</div>
        </div>
        <div class="stat-box">
            <div class="stat-val" style="font-size:16px;padding-top:4px">
                <?php echo $totpEnabled ? '&#x2705;' : '&#x26AA;'; ?>
            </div>
            <div class="stat-label">2FA</div>
        </div>
    </div>

    <?php if ($failedRecent >= 3): ?>
    <div class="failed-warn">&#x26A0; <?php echo $failedRecent; ?> failed login attempts in the past 7 days. If this wasn't you, change your password.</div>
    <?php endif; ?>

    <!-- Security -->
    <div class="section-label">Security</div>
    <div style="margin-bottom:6px;font-size:13px">
        Two-Factor Authentication:
        <span class="badge-2fa <?php echo $totpEnabled ? 'badge-on' : 'badge-off'; ?>">
            <?php echo $totpEnabled ? '&#x2705; On' : 'Off'; ?>
        </span>
    </div>
    <a href="totp_setup.php"  class="link-btn">&#x1F510; <?php echo $totpEnabled ? 'Manage' : 'Enable'; ?> Two-Factor Authentication</a>
    <a href="change_password.php" class="link-btn">&#x1F511; Change Password</a>
    <a href="export_log.php"  class="link-btn">&#x1F4E5; Export Login History (CSV)</a>

    <!-- Recent logins -->
    <?php if (!empty($recentLogins)): ?>
    <div class="section-label">Recent Login Activity</div>
    <table class="login-mini-table">
        <?php foreach ($recentLogins as $i => $row): ?>
        <tr>
            <td class="lmt-time">
                <?php
                if ($i === 0) echo '<strong style="color:#86efac">&#x25CF; Current</strong>';
                else echo htmlspecialchars(date('M j, g:i a', strtotime($row['login_time'])));
                ?>
            </td>
            <td class="lmt-ip"><?php echo htmlspecialchars($row['ip']); ?></td>
        </tr>
        <?php endforeach; ?>
    </table>
    <?php endif; ?>

    <div class="back-link"><a href="homepage.php">&larr; Back to Dashboard</a></div>
</div>
</body>
</html>
