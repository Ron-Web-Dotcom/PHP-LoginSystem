<?php
require_once 'auth_check.php';

$email = $_SESSION['email'];
$con   = mysqli_connect('localhost', 'root', '', 'system');

// Ensure created_at column exists on remember-tokens table
$tbl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_remember_tokens'");
$msg = '';

if ($tbl && mysqli_num_rows($tbl) > 0) {
    $cc = mysqli_query($con,
        "SELECT 1 FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA='system' AND TABLE_NAME='tbl_remember_tokens' AND COLUMN_NAME='created_at'"
    );
    if ($cc && mysqli_num_rows($cc) === 0) {
        mysqli_query($con,
            "ALTER TABLE tbl_remember_tokens ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP"
        );
    }

    // Handle revoke
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!empty($_POST['revoke_id'])) {
            $rid  = (int) $_POST['revoke_id'];
            $s    = mysqli_prepare($con,
                "DELETE FROM tbl_remember_tokens WHERE id = ? AND email = ?"
            );
            mysqli_stmt_bind_param($s, 'is', $rid, $email);
            mysqli_stmt_execute($s);
            mysqli_stmt_close($s);
            $msg = 'Session revoked.';
        } elseif (!empty($_POST['revoke_all'])) {
            $s = mysqli_prepare($con,
                "DELETE FROM tbl_remember_tokens WHERE email = ?"
            );
            mysqli_stmt_bind_param($s, 's', $email);
            mysqli_stmt_execute($s);
            mysqli_stmt_close($s);
            // Clear the cookie too
            setcookie('remember_token', '', time() - 3600, '/', '', false, true);
            $msg = 'All sessions revoked.';
        }
    }
}

// Fetch active sessions
$sessions = [];
$tbl2 = mysqli_query($con, "SHOW TABLES LIKE 'tbl_remember_tokens'");
if ($tbl2 && mysqli_num_rows($tbl2) > 0) {
    $now  = date('Y-m-d H:i:s');
    $stmt = mysqli_prepare($con,
        "SELECT id, token_hash, created_at, expires_at FROM tbl_remember_tokens
         WHERE email = ? AND expires_at > ?
         ORDER BY created_at DESC"
    );
    mysqli_stmt_bind_param($stmt, 'ss', $email, $now);
    mysqli_stmt_execute($stmt);
    $res = mysqli_stmt_get_result($stmt);
    while ($row = mysqli_fetch_assoc($res)) {
        $sessions[] = $row;
    }
    mysqli_stmt_close($stmt);
}
mysqli_close($con);

// Detect current session token
$currentTokenHash = '';
if (!empty($_COOKIE['remember_token'])) {
    $sep = strpos($_COOKIE['remember_token'], ':');
    if ($sep !== false) {
        $raw = substr($_COOKIE['remember_token'], $sep + 1);
        $currentTokenHash = hash('sha256', $raw);
    }
}
?>
<!DOCTYPE html>
<html>
<head>
<title>Session Manager</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" href="style/cleanup.css">
<style>
    h2 { color:#fff; text-align:center; margin-top:56px; text-transform:uppercase;
         font-size:1.3rem; letter-spacing:2px; }
    .sm-wrap { max-width:620px; margin:22px auto 60px; padding:0 16px; }
    .sm-card {
        background:rgba(255,255,255,0.07); border:1px solid rgba(255,255,255,0.12);
        border-radius:14px; padding:22px 26px; color:#e0e0e0;
    }
    .card-label { font-size:11px; font-weight:700; letter-spacing:1.5px;
                  text-transform:uppercase; color:#60a5fa; margin-bottom:14px; }
    .session-row {
        display:flex; align-items:center; gap:12px;
        padding:10px 0; border-bottom:1px solid rgba(255,255,255,0.06);
    }
    .session-row:last-child { border-bottom:none; }
    .sess-icon { font-size:22px; flex-shrink:0; }
    .sess-info { flex:1; min-width:0; }
    .sess-dates { font-size:11px; color:#64748b; }
    .badge-current {
        background:rgba(34,197,94,0.2); color:#86efac;
        border:1px solid rgba(34,197,94,0.3);
        border-radius:12px; padding:2px 8px; font-size:11px; font-weight:600;
    }
    .btn-revoke {
        background:rgba(239,68,68,0.15); border:1px solid rgba(239,68,68,0.3);
        color:#fca5a5; border-radius:6px; padding:4px 12px;
        font-size:11px; cursor:pointer; transition:background .15s; white-space:nowrap;
    }
    .btn-revoke:hover { background:rgba(239,68,68,0.3); }
    .btn-revoke-all {
        background:rgba(239,68,68,0.08); border:1px solid rgba(239,68,68,0.25);
        color:#f87171; border-radius:8px; padding:8px 18px;
        font-size:13px; cursor:pointer; transition:background .15s; margin-top:14px;
    }
    .btn-revoke-all:hover { background:rgba(239,68,68,0.2); }
    .empty-state { text-align:center; color:#64748b; font-size:13px; padding:20px 0; }
    .back-link { text-align:center; margin-top:16px; }
    .back-link a { color:#a78bfa; font-size:13px; }
</style>
</head>
<body>
<h2>&#x1F5A5; Session Manager</h2>
<div class="sm-wrap">
    <?php if ($msg): ?>
    <div class="alert alert-info py-2 mb-3" style="font-size:13px">&#x2705; <?= htmlspecialchars($msg) ?></div>
    <?php endif; ?>

    <div class="sm-card">
        <div class="card-label">&#x1F510; Active Remember-Me Sessions</div>

        <?php if (empty($sessions)): ?>
        <div class="empty-state">No active persistent sessions.</div>
        <?php else: ?>
        <?php foreach ($sessions as $s): ?>
        <?php
            $isCurrent = !empty($currentTokenHash) &&
                         isset($s['token_hash']) && $s['token_hash'] === $currentTokenHash;
            $created   = date('M j Y, g:i a', strtotime($s['created_at']));
            $expires   = date('M j Y', strtotime($s['expires_at']));
        ?>
        <div class="session-row">
            <div class="sess-icon">&#x1F4BB;</div>
            <div class="sess-info">
                <div style="font-size:13px; color:#d0d0d0">
                    Started <?= htmlspecialchars($created) ?>
                    <?php if ($isCurrent): ?>
                    <span class="badge-current">&#x25CF; This session</span>
                    <?php endif; ?>
                </div>
                <div class="sess-dates">Expires <?= htmlspecialchars($expires) ?></div>
            </div>
            <form method="post">
                <input type="hidden" name="revoke_id" value="<?= (int)$s['id'] ?>">
                <button type="submit" class="btn-revoke">Revoke</button>
            </form>
        </div>
        <?php endforeach; ?>

        <form method="post"
              onsubmit="return confirm('Revoke all sessions? You will need to log in again on all devices.')">
            <input type="hidden" name="revoke_all" value="1">
            <button type="submit" class="btn-revoke-all">&#x1F6AB; Revoke All Sessions</button>
        </form>
        <?php endif; ?>
    </div>

    <p style="color:#64748b;font-size:12px;text-align:center;margin-top:12px">
        Revoking a session signs you out from that device.
        Sessions expire automatically after 30 days.
    </p>

    <div class="back-link"><a href="homepage.php">&larr; Back to Dashboard</a></div>
</div>
</body>
</html>
