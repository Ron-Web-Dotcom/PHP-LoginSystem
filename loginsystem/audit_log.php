<?php
require_once 'auth_check.php';

$email = $_SESSION['email'];
$con   = mysqli_connect('localhost', 'root', '', 'system');

$events = [];
$tbl    = mysqli_query($con, "SHOW TABLES LIKE 'tbl_audit_log'");
if ($tbl && mysqli_num_rows($tbl) > 0) {
    $stmt = mysqli_prepare($con,
        "SELECT event, detail, ip, created_at
         FROM tbl_audit_log WHERE email = ?
         ORDER BY created_at DESC LIMIT 100"
    );
    mysqli_stmt_bind_param($stmt, 's', $email);
    mysqli_stmt_execute($stmt);
    $res = mysqli_stmt_get_result($stmt);
    while ($row = mysqli_fetch_assoc($res)) {
        $events[] = $row;
    }
    mysqli_stmt_close($stmt);
}
mysqli_close($con);

// Map event type → icon + colour
$eventMeta = [
    'login'             => ['&#x1F7E2;', '#4ade80', 'Login'],
    'login_failed'      => ['&#x1F534;', '#f87171', 'Login Failed'],
    'logout'            => ['&#x1F7E1;', '#facc15', 'Logout'],
    'new_ip_detected'   => ['&#x1F7E0;', '#fb923c', 'New IP'],
    'password_changed'  => ['&#x1F511;', '#60a5fa', 'Password Changed'],
    '2fa_enabled'       => ['&#x1F510;', '#4ade80', '2FA Enabled'],
    '2fa_disabled'      => ['&#x26A0;',  '#f87171', '2FA Disabled'],
    'backup_code_used'  => ['&#x1F5DD;', '#a78bfa', 'Backup Code Used'],
    'magic_link_login'  => ['&#x2728;',  '#c084fc', 'Magic Link Login'],
    'remember_me_login' => ['&#x1F4BE;', '#94a3b8', 'Remember-Me Login'],
    'account_deleted'   => ['&#x1F5D1;', '#f87171', 'Account Deleted'],
    'lockout'           => ['&#x1F6AB;', '#f87171', 'Account Locked'],
    'registration'      => ['&#x1F195;', '#4ade80', 'Registered'],
];
?>
<!DOCTYPE html>
<html>
<head>
<title>Account Audit Log</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" href="style/cleanup.css">
<style>
    h2 { color:#fff; text-align:center; margin-top:56px; text-transform:uppercase;
         font-size:1.3rem; letter-spacing:2px; }
    .al-wrap { max-width:700px; margin:22px auto 60px; padding:0 16px; }
    .al-card {
        background:rgba(255,255,255,0.07); border:1px solid rgba(255,255,255,0.12);
        border-radius:14px; padding:22px 26px; color:#e0e0e0;
    }
    .card-label { font-size:11px; font-weight:700; letter-spacing:1.5px;
                  text-transform:uppercase; color:#60a5fa; margin-bottom:14px; }
    .al-row {
        display:flex; align-items:flex-start; gap:12px;
        padding:9px 0; border-bottom:1px solid rgba(255,255,255,0.05);
    }
    .al-row:last-child { border-bottom:none; }
    .al-dot { width:10px; height:10px; border-radius:50%; margin-top:4px; flex-shrink:0; }
    .al-icon { font-size:16px; flex-shrink:0; width:22px; text-align:center; }
    .al-body { flex:1; min-width:0; }
    .al-event { font-size:13px; font-weight:600; color:#d0d0d0; }
    .al-detail { font-size:11px; color:#64748b; margin-top:1px; }
    .al-meta { font-size:11px; color:#475569; text-align:right; flex-shrink:0; line-height:1.6; }
    .al-meta .al-ip { font-family:monospace; }
    .empty-state { text-align:center; color:#64748b; font-size:13px; padding:24px 0; }
    .back-link { text-align:center; margin-top:16px; }
    .back-link a { color:#a78bfa; font-size:13px; }
</style>
</head>
<body>
<h2>&#x1F4DC; Account Audit Log</h2>
<div class="al-wrap">
    <div class="al-card">
        <div class="card-label">Last 100 security events for <?= htmlspecialchars($email) ?></div>

        <?php if (empty($events)): ?>
        <div class="empty-state">No audit events yet.</div>
        <?php else: ?>
        <?php foreach ($events as $ev):
            $meta   = $eventMeta[$ev['event']] ?? ['&#x2022;', '#94a3b8', ucwords(str_replace('_',' ',$ev['event']))];
            [$icon, $color, $label] = $meta;
            $ts = date('M j Y, g:i a', strtotime($ev['created_at']));
        ?>
        <div class="al-row">
            <div class="al-dot" style="background:<?= $color ?>"></div>
            <div class="al-icon"><?= $icon ?></div>
            <div class="al-body">
                <div class="al-event" style="color:<?= $color ?>"><?= $label ?></div>
                <?php if ($ev['detail']): ?>
                <div class="al-detail"><?= htmlspecialchars($ev['detail']) ?></div>
                <?php endif; ?>
            </div>
            <div class="al-meta">
                <div><?= htmlspecialchars($ts) ?></div>
                <?php if ($ev['ip']): ?>
                <div class="al-ip"><?= htmlspecialchars($ev['ip']) ?></div>
                <?php endif; ?>
            </div>
        </div>
        <?php endforeach; ?>
        <?php endif; ?>
    </div>
    <div class="back-link"><a href="homepage.php">&larr; Back to Dashboard</a></div>
</div>
</body>
</html>
