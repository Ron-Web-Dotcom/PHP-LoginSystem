<?php
require_once 'auth_check.php';

// Admin-only gate
if (empty($_SESSION['is_admin'])) {
    header('location:homepage.php');
    exit();
}

$con = mysqli_connect('localhost', 'root', '', 'system');

// Handle unlock action
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['unlock_email'])) {
    $unlockEmail = $_POST['unlock_email'];
    $del = mysqli_prepare($con, "DELETE FROM tbl_login_attempts WHERE email = ?");
    mysqli_stmt_bind_param($del, 's', $unlockEmail);
    mysqli_stmt_execute($del);
    mysqli_stmt_close($del);
    $unlockMsg = htmlspecialchars($unlockEmail) . ' has been unlocked.';
}

// Ensure is_admin column exists
$r = mysqli_query($con,
    "SELECT 1 FROM information_schema.COLUMNS
     WHERE TABLE_SCHEMA='system' AND TABLE_NAME='tbl_signup' AND COLUMN_NAME='is_admin'"
);
if ($r && mysqli_num_rows($r) === 0) {
    mysqli_query($con, "ALTER TABLE tbl_signup ADD COLUMN is_admin TINYINT(1) DEFAULT 0");
}

// Fetch all users
$users = [];
$result = mysqli_query($con,
    "SELECT s.email,
            COALESCE(s.is_admin,0)       AS is_admin,
            COALESCE(s.totp_enabled,0)   AS totp_enabled,
            COUNT(DISTINCT sl.id)        AS total_logins,
            MAX(sl.login_time)           AS last_login
     FROM tbl_signup s
     LEFT JOIN tbl_session_log sl ON sl.email = s.email
     GROUP BY s.email, s.is_admin, s.totp_enabled
     ORDER BY last_login DESC"
);
if ($result) {
    while ($row = mysqli_fetch_assoc($result)) {
        $users[] = $row;
    }
}

// Fetch lockout status for each user (≥5 attempts in last 15 min)
$lockedSet = [];
$tcheck = mysqli_query($con, "SHOW TABLES LIKE 'tbl_login_attempts'");
if ($tcheck && mysqli_num_rows($tcheck) > 0) {
    $window = date('Y-m-d H:i:s', strtotime('-15 minutes'));
    $lr = mysqli_query($con,
        "SELECT email, COUNT(*) AS cnt FROM tbl_login_attempts
         WHERE attempt_time >= '{$window}' GROUP BY email HAVING cnt >= 5"
    );
    while ($row = mysqli_fetch_assoc($lr)) {
        $lockedSet[$row['email']] = true;
    }
}

// Recent global failed attempts (last 50)
$recentFails = [];
if ($tcheck && mysqli_num_rows($tcheck) > 0) {
    $fr = mysqli_query($con,
        "SELECT email, ip, attempt_time FROM tbl_login_attempts
         ORDER BY attempt_time DESC LIMIT 50"
    );
    while ($row = mysqli_fetch_assoc($fr)) {
        $recentFails[] = $row;
    }
}

mysqli_close($con);
?>
<!DOCTYPE html>
<html>
<head>
<title>Admin Dashboard</title>
<link rel="stylesheet" type="text/css" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" type="text/css" href="style/cleanup.css">
<style>
    h2 { color:#fff; text-align:center; margin-top:50px; text-transform:uppercase;
         font-size:1.3rem; letter-spacing:2px; }
    .admin-wrap { max-width:900px; margin:22px auto 60px; padding:0 16px; }
    .section-card {
        background:rgba(255,255,255,0.07);
        border:1px solid rgba(255,255,255,0.12);
        border-radius:14px; padding:22px 26px;
        margin-bottom:20px; color:#e0e0e0;
    }
    .card-label {
        font-size:11px; font-weight:700; letter-spacing:1.5px;
        text-transform:uppercase; margin-bottom:14px;
    }
    .label-users   { color:#60a5fa; }
    .label-fails   { color:#f87171; }
    .admin-table   { width:100%; border-collapse:collapse; font-size:13px; }
    .admin-table th {
        font-size:10px; font-weight:700; letter-spacing:1px;
        text-transform:uppercase; color:#64748b;
        padding:6px 8px; border-bottom:1px solid rgba(255,255,255,0.08);
        text-align:left;
    }
    .admin-table td {
        padding:8px 8px; border-bottom:1px solid rgba(255,255,255,0.05);
        vertical-align:middle;
    }
    .admin-table tr:last-child td { border-bottom:none; }
    .badge-small {
        display:inline-block; padding:2px 8px; border-radius:12px;
        font-size:11px; font-weight:600;
    }
    .badge-admin   { background:rgba(167,139,250,0.2); color:#c4b5fd; border:1px solid rgba(167,139,250,0.3); }
    .badge-locked  { background:rgba(239,68,68,0.2);   color:#fca5a5; border:1px solid rgba(239,68,68,0.3); }
    .badge-2fa-on  { background:rgba(34,197,94,0.15);  color:#86efac; border:1px solid rgba(34,197,94,0.3); }
    .badge-2fa-off { background:rgba(100,116,139,0.15);color:#94a3b8; border:1px solid rgba(100,116,139,0.25);}
    .btn-unlock {
        background:rgba(249,115,22,0.15); border:1px solid rgba(249,115,22,0.35);
        color:#fdba74; border-radius:6px; padding:3px 10px;
        font-size:11px; cursor:pointer; transition:background .15s;
    }
    .btn-unlock:hover { background:rgba(249,115,22,0.3); }
    .fail-ip   { font-family:monospace; color:#64748b; }
    .fail-time { color:#94a3b8; font-size:11px; }
    .back-link { text-align:center; margin-top:4px; }
    .back-link a { color:#a78bfa; font-size:13px; }
</style>
</head>
<body>
<h2>&#x1F6E1; Admin Dashboard</h2>

<div class="admin-wrap">
    <?php if (!empty($unlockMsg)): ?>
    <div class="alert alert-success py-2 mb-3" style="font-size:13px">
        &#x2705; <?php echo $unlockMsg; ?>
    </div>
    <?php endif; ?>

    <!-- ── Users ── -->
    <div class="section-card">
        <div class="card-label label-users">&#x1F465; All Users (<?php echo count($users); ?>)</div>
        <table class="admin-table">
            <thead>
                <tr>
                    <th>Email</th>
                    <th>2FA</th>
                    <th>Admin</th>
                    <th>Logins</th>
                    <th>Last Login</th>
                    <th>Status</th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($users as $u): ?>
            <tr>
                <td style="color:#d0d0d0"><?php echo htmlspecialchars($u['email']); ?></td>
                <td>
                    <span class="badge-small <?php echo $u['totp_enabled'] ? 'badge-2fa-on' : 'badge-2fa-off'; ?>">
                        <?php echo $u['totp_enabled'] ? '&#x2705; On' : 'Off'; ?>
                    </span>
                </td>
                <td>
                    <?php if ($u['is_admin']): ?>
                    <span class="badge-small badge-admin">Admin</span>
                    <?php else: echo '<span style="color:#475569;font-size:12px">—</span>'; endif; ?>
                </td>
                <td style="color:#94a3b8"><?php echo (int) $u['total_logins']; ?></td>
                <td class="fail-time">
                    <?php echo $u['last_login'] ? htmlspecialchars(date('M j, g:i a', strtotime($u['last_login']))) : '—'; ?>
                </td>
                <td>
                    <?php if (isset($lockedSet[$u['email']])): ?>
                    <span class="badge-small badge-locked">&#x1F6AB; Locked</span>
                    <?php else: echo '<span style="color:#4ade80;font-size:11px">&#x25CF; OK</span>'; endif; ?>
                </td>
                <td>
                    <?php if (isset($lockedSet[$u['email']])): ?>
                    <form method="post" style="margin:0">
                        <input type="hidden" name="unlock_email" value="<?php echo htmlspecialchars($u['email']); ?>">
                        <button type="submit" class="btn-unlock">Unlock</button>
                    </form>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- ── Recent failed attempts ── -->
    <?php if (!empty($recentFails)): ?>
    <div class="section-card">
        <div class="card-label label-fails">&#x26A0; Recent Failed Login Attempts</div>
        <table class="admin-table">
            <thead>
                <tr><th>Email</th><th>IP</th><th>Time</th></tr>
            </thead>
            <tbody>
            <?php foreach ($recentFails as $f): ?>
            <tr>
                <td style="color:#d0d0d0"><?php echo htmlspecialchars($f['email']); ?></td>
                <td class="fail-ip"><?php echo htmlspecialchars($f['ip']); ?></td>
                <td class="fail-time"><?php echo htmlspecialchars(date('M j, g:i a', strtotime($f['attempt_time']))); ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>

    <div class="back-link"><a href="homepage.php">&larr; Back to Dashboard</a></div>
</div>
</body>
</html>
