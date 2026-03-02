<?php
require_once 'auth_check.php';

// Admin-only gate
if (empty($_SESSION['is_admin'])) {
    header('location:homepage.php');
    exit();
}

$con = mysqli_connect('localhost', 'root', '', 'system');

// Ensure new columns exist
foreach ([
    'is_admin'  => 'TINYINT(1) DEFAULT 0',
    'status'    => "VARCHAR(10) NOT NULL DEFAULT 'active'",
    'role'      => "VARCHAR(20) NOT NULL DEFAULT 'user'",
] as $col => $def) {
    $r = mysqli_query($con,
        "SELECT 1 FROM information_schema.COLUMNS
         WHERE TABLE_SCHEMA='system' AND TABLE_NAME='tbl_signup' AND COLUMN_NAME='{$col}'"
    );
    if ($r && mysqli_num_rows($r) === 0) {
        mysqli_query($con, "ALTER TABLE tbl_signup ADD COLUMN {$col} {$def}");
    }
}

// Ensure IP blocklist table exists
mysqli_query($con, "CREATE TABLE IF NOT EXISTS tbl_ip_blocklist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45) NOT NULL UNIQUE,
    reason VARCHAR(255),
    blocked_at DATETIME NOT NULL,
    INDEX idx_ip (ip)
)");

$msg     = '';
$msgType = 'success';

// ── Handle POSTs ─────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Unlock user
    if (!empty($_POST['unlock_email'])) {
        $ue  = $_POST['unlock_email'];
        $del = mysqli_prepare($con, "DELETE FROM tbl_login_attempts WHERE email = ?");
        mysqli_stmt_bind_param($del, 's', $ue);
        mysqli_stmt_execute($del);
        mysqli_stmt_close($del);
        $msg = htmlspecialchars($ue) . ' unlocked.';
    }

    // Block IP
    elseif (!empty($_POST['block_ip'])) {
        $bip    = trim($_POST['block_ip']);
        $breason= trim($_POST['block_reason'] ?? '');
        $bnow   = date('Y-m-d H:i:s');
        if (filter_var($bip, FILTER_VALIDATE_IP)) {
            $bs = mysqli_prepare($con,
                "INSERT INTO tbl_ip_blocklist (ip, reason, blocked_at) VALUES (?,?,?)
                 ON DUPLICATE KEY UPDATE reason=VALUES(reason), blocked_at=VALUES(blocked_at)"
            );
            mysqli_stmt_bind_param($bs, 'sss', $bip, $breason, $bnow);
            mysqli_stmt_execute($bs);
            mysqli_stmt_close($bs);
            $msg = "IP {$bip} blocked.";
        } else {
            $msg     = 'Invalid IP address.';
            $msgType = 'danger';
        }
    }

    // Unblock IP
    elseif (!empty($_POST['unblock_ip'])) {
        $ubip = $_POST['unblock_ip'];
        $ubs  = mysqli_prepare($con, "DELETE FROM tbl_ip_blocklist WHERE ip = ?");
        mysqli_stmt_bind_param($ubs, 's', $ubip);
        mysqli_stmt_execute($ubs);
        mysqli_stmt_close($ubs);
        $msg = "IP {$ubip} unblocked.";
    }

    // Approve user
    elseif (!empty($_POST['approve_user'])) {
        $au  = $_POST['approve_user'];
        $aps = mysqli_prepare($con, "UPDATE tbl_signup SET status = 'active' WHERE email = ?");
        mysqli_stmt_bind_param($aps, 's', $au);
        mysqli_stmt_execute($aps);
        mysqli_stmt_close($aps);
        $msg = htmlspecialchars($au) . ' approved.';
    }

    // Reject user
    elseif (!empty($_POST['reject_user'])) {
        $ru  = $_POST['reject_user'];
        $rjs = mysqli_prepare($con, "UPDATE tbl_signup SET status = 'rejected' WHERE email = ?");
        mysqli_stmt_bind_param($rjs, 's', $ru);
        mysqli_stmt_execute($rjs);
        mysqli_stmt_close($rjs);
        $msg = htmlspecialchars($ru) . ' rejected.';
    }

    // Change role
    elseif (!empty($_POST['role_email']) && !empty($_POST['new_role'])) {
        $re  = $_POST['role_email'];
        $nr  = in_array($_POST['new_role'], ['user', 'moderator', 'admin']) ? $_POST['new_role'] : 'user';
        $newIsAdmin = ($nr === 'admin') ? 1 : 0;
        $rs  = mysqli_prepare($con,
            "UPDATE tbl_signup SET role = ?, is_admin = ? WHERE email = ?"
        );
        mysqli_stmt_bind_param($rs, 'sis', $nr, $newIsAdmin, $re);
        mysqli_stmt_execute($rs);
        mysqli_stmt_close($rs);
        $msg = "Role of " . htmlspecialchars($re) . " changed to {$nr}.";
    }
}

// ── Fetch all users ───────────────────────────────────────────────────────────
$users = [];
$result = mysqli_query($con,
    "SELECT s.email,
            COALESCE(s.is_admin,0)       AS is_admin,
            COALESCE(s.totp_enabled,0)   AS totp_enabled,
            COALESCE(s.status,'active')  AS status,
            COALESCE(s.role,'user')      AS role,
            COUNT(DISTINCT sl.id)        AS total_logins,
            MAX(sl.login_time)           AS last_login
     FROM tbl_signup s
     LEFT JOIN tbl_session_log sl ON sl.email = s.email
     GROUP BY s.email, s.is_admin, s.totp_enabled, s.status, s.role
     ORDER BY last_login DESC"
);
if ($result) {
    while ($row = mysqli_fetch_assoc($result)) {
        $users[] = $row;
    }
}

// Locked accounts
$lockedSet = [];
$tcheck = mysqli_query($con, "SHOW TABLES LIKE 'tbl_login_attempts'");
if ($tcheck && mysqli_num_rows($tcheck) > 0) {
    $window = date('Y-m-d H:i:s', strtotime('-15 minutes'));
    $lr = mysqli_query($con,
        "SELECT email FROM tbl_login_attempts
         WHERE attempt_time >= '{$window}' GROUP BY email HAVING COUNT(*) >= 5"
    );
    while ($row = mysqli_fetch_assoc($lr)) {
        $lockedSet[$row['email']] = true;
    }
}

// Recent failed attempts
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

// Blocked IPs
$blockedIps = [];
$biRes = mysqli_query($con,
    "SELECT ip, reason, blocked_at FROM tbl_ip_blocklist ORDER BY blocked_at DESC"
);
if ($biRes) {
    while ($row = mysqli_fetch_assoc($biRes)) {
        $blockedIps[] = $row;
    }
}

// Pending users
$pendingUsers = [];
$puRes = mysqli_query($con,
    "SELECT email, status FROM tbl_signup WHERE status = 'pending' OR status = 'rejected' ORDER BY email"
);
if ($puRes) {
    while ($row = mysqli_fetch_assoc($puRes)) {
        $pendingUsers[] = $row;
    }
}

mysqli_close($con);

$currentUserEmail = $_SESSION['email'];
?>
<!DOCTYPE html>
<html>
<head>
<title>Admin Dashboard</title>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" href="style/cleanup.css">
<style>
    h2 { color:#fff; text-align:center; margin-top:50px; text-transform:uppercase;
         font-size:1.3rem; letter-spacing:2px; }
    .admin-wrap { max-width:960px; margin:22px auto 60px; padding:0 16px; }
    .section-card {
        background:rgba(255,255,255,0.07); border:1px solid rgba(255,255,255,0.12);
        border-radius:14px; padding:22px 26px; margin-bottom:20px; color:#e0e0e0;
    }
    .card-label {
        font-size:11px; font-weight:700; letter-spacing:1.5px;
        text-transform:uppercase; margin-bottom:14px;
    }
    .label-users  { color:#60a5fa; }
    .label-fails  { color:#f87171; }
    .label-ip     { color:#fb923c; }
    .label-pend   { color:#facc15; }
    .label-audit  { color:#a78bfa; }
    .admin-table { width:100%; border-collapse:collapse; font-size:13px; }
    .admin-table th {
        font-size:10px; font-weight:700; letter-spacing:1px; text-transform:uppercase;
        color:#64748b; padding:6px 8px; border-bottom:1px solid rgba(255,255,255,0.08); text-align:left;
    }
    .admin-table td { padding:8px 8px; border-bottom:1px solid rgba(255,255,255,0.05); vertical-align:middle; }
    .admin-table tr:last-child td { border-bottom:none; }
    .badge-small { display:inline-block; padding:2px 8px; border-radius:12px; font-size:11px; font-weight:600; }
    .badge-admin   { background:rgba(167,139,250,0.2); color:#c4b5fd; border:1px solid rgba(167,139,250,0.3); }
    .badge-mod     { background:rgba(251,191,36,0.2);  color:#fcd34d; border:1px solid rgba(251,191,36,0.3); }
    .badge-locked  { background:rgba(239,68,68,0.2);   color:#fca5a5; border:1px solid rgba(239,68,68,0.3); }
    .badge-2fa-on  { background:rgba(34,197,94,0.15);  color:#86efac; border:1px solid rgba(34,197,94,0.3); }
    .badge-2fa-off { background:rgba(100,116,139,0.15);color:#94a3b8; border:1px solid rgba(100,116,139,0.25);}
    .badge-pending { background:rgba(251,191,36,0.15); color:#fcd34d; border:1px solid rgba(251,191,36,0.3); }
    .badge-reject  { background:rgba(239,68,68,0.15);  color:#fca5a5; border:1px solid rgba(239,68,68,0.3); }
    .btn-sm-action {
        border-radius:6px; padding:3px 10px; font-size:11px; cursor:pointer;
        transition:background .15s; border:1px solid;
    }
    .btn-unlock   { background:rgba(249,115,22,0.15); border-color:rgba(249,115,22,0.35); color:#fdba74; }
    .btn-unlock:hover  { background:rgba(249,115,22,0.3); }
    .btn-approve  { background:rgba(34,197,94,0.15); border-color:rgba(34,197,94,0.35); color:#86efac; }
    .btn-approve:hover { background:rgba(34,197,94,0.3); }
    .btn-reject   { background:rgba(239,68,68,0.15); border-color:rgba(239,68,68,0.35); color:#fca5a5; }
    .btn-reject:hover  { background:rgba(239,68,68,0.3); }
    .btn-unblock  { background:rgba(34,197,94,0.12); border-color:rgba(34,197,94,0.3); color:#86efac; }
    .btn-unblock:hover { background:rgba(34,197,94,0.25); }
    .fail-ip   { font-family:monospace; color:#64748b; }
    .fail-time { color:#94a3b8; font-size:11px; }
    .back-link { text-align:center; margin-top:4px; }
    .back-link a { color:#a78bfa; font-size:13px; }
    .ip-form { display:flex; gap:8px; flex-wrap:wrap; align-items:flex-end; }
    .ip-form input {
        background:rgba(255,255,255,0.07); border:1px solid rgba(255,255,255,0.18);
        color:#fff; border-radius:8px; padding:5px 10px; font-size:12px;
    }
    .ip-form input::placeholder { color:#555; }
    .btn-block {
        background:rgba(239,68,68,0.15); border:1px solid rgba(239,68,68,0.35);
        color:#fca5a5; border-radius:8px; padding:5px 14px; font-size:12px; cursor:pointer;
        transition:background .15s;
    }
    .btn-block:hover { background:rgba(239,68,68,0.3); }
    /* AI audit */
    #audit-result { font-size:13px; color:#d0d0d0; line-height:1.7; white-space:pre-wrap; }
    .btn-audit {
        background:linear-gradient(135deg,#a78bfa,#7c3aed);
        border:none; border-radius:8px; color:#fff; padding:8px 18px;
        font-size:13px; cursor:pointer; transition:opacity .2s;
    }
    .btn-audit:hover { opacity:0.85; }
    .grade-badge {
        display:inline-block; font-size:32px; font-weight:800;
        width:48px; height:48px; line-height:48px; text-align:center;
        border-radius:10px; margin-right:12px;
    }
    select.role-sel {
        background:rgba(255,255,255,0.07); border:1px solid rgba(255,255,255,0.18);
        color:#fff; border-radius:6px; padding:3px 6px; font-size:11px; cursor:pointer;
    }
    option { background:#1e1e2e; }
</style>
</head>
<body>
<h2>&#x1F6E1; Admin Dashboard</h2>

<div class="admin-wrap">
    <?php if ($msg): ?>
    <div class="alert alert-<?= $msgType ?> py-2 mb-3" style="font-size:13px">
        <?= $msgType === 'success' ? '&#x2705; ' : '&#x26A0; ' ?><?= $msg ?>
    </div>
    <?php endif; ?>

    <!-- ── Users ── -->
    <div class="section-card">
        <div class="card-label label-users">&#x1F465; All Users (<?= count($users) ?>)</div>
        <table class="admin-table">
            <thead>
                <tr>
                    <th>Email</th><th>2FA</th><th>Role</th><th>Status</th>
                    <th>Logins</th><th>Last Login</th><th>Locked</th><th>Actions</th>
                </tr>
            </thead>
            <tbody>
            <?php foreach ($users as $u): ?>
            <tr>
                <td style="color:#d0d0d0"><?= htmlspecialchars($u['email']) ?></td>
                <td>
                    <span class="badge-small <?= $u['totp_enabled'] ? 'badge-2fa-on' : 'badge-2fa-off' ?>">
                        <?= $u['totp_enabled'] ? '&#x2705; On' : 'Off' ?>
                    </span>
                </td>
                <td>
                    <?php if ($u['email'] !== $currentUserEmail): ?>
                    <form method="post" style="margin:0;display:inline">
                        <input type="hidden" name="role_email" value="<?= htmlspecialchars($u['email']) ?>">
                        <select name="new_role" class="role-sel"
                                onchange="this.form.submit()" title="Change role">
                            <option value="user"      <?= ($u['role']??'user')==='user'      ? 'selected':'' ?>>User</option>
                            <option value="moderator" <?= ($u['role']??'user')==='moderator' ? 'selected':'' ?>>Moderator</option>
                            <option value="admin"     <?= ($u['role']??'user')==='admin'     ? 'selected':'' ?>>Admin</option>
                        </select>
                    </form>
                    <?php else: ?>
                    <span class="badge-small badge-admin">Admin (you)</span>
                    <?php endif; ?>
                </td>
                <td>
                    <?php $st = $u['status'] ?? 'active'; ?>
                    <?php if ($st === 'active'): ?>
                    <span style="color:#4ade80;font-size:11px">&#x25CF; Active</span>
                    <?php elseif ($st === 'pending'): ?>
                    <span class="badge-small badge-pending">Pending</span>
                    <?php else: ?>
                    <span class="badge-small badge-reject">Rejected</span>
                    <?php endif; ?>
                </td>
                <td style="color:#94a3b8"><?= (int)$u['total_logins'] ?></td>
                <td class="fail-time">
                    <?= $u['last_login'] ? date('M j, g:i a', strtotime($u['last_login'])) : '—' ?>
                </td>
                <td>
                    <?php if (isset($lockedSet[$u['email']])): ?>
                    <span class="badge-small badge-locked">&#x1F6AB; Locked</span>
                    <?php else: ?>
                    <span style="color:#4ade80;font-size:11px">&#x25CF; OK</span>
                    <?php endif; ?>
                </td>
                <td>
                    <?php if (isset($lockedSet[$u['email']])): ?>
                    <form method="post" style="margin:0;display:inline">
                        <input type="hidden" name="unlock_email" value="<?= htmlspecialchars($u['email']) ?>">
                        <button type="submit" class="btn-sm-action btn-unlock">Unlock</button>
                    </form>
                    <?php endif; ?>
                    <?php if (($u['status']??'active') === 'pending'): ?>
                    <form method="post" style="margin:0;display:inline">
                        <input type="hidden" name="approve_user" value="<?= htmlspecialchars($u['email']) ?>">
                        <button type="submit" class="btn-sm-action btn-approve">Approve</button>
                    </form>
                    <form method="post" style="margin:0;display:inline">
                        <input type="hidden" name="reject_user" value="<?= htmlspecialchars($u['email']) ?>">
                        <button type="submit" class="btn-sm-action btn-reject">Reject</button>
                    </form>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- ── IP Blocklist ── -->
    <div class="section-card">
        <div class="card-label label-ip">&#x1F6AB; IP Blocklist (<?= count($blockedIps) ?>)</div>
        <form method="post" class="ip-form" style="margin-bottom:14px">
            <input type="text"  name="block_ip"     placeholder="IP address (e.g. 1.2.3.4)" style="width:180px">
            <input type="text"  name="block_reason" placeholder="Reason (optional)"        style="width:200px">
            <button type="submit" class="btn-block">&#x2795; Block IP</button>
        </form>
        <?php if (empty($blockedIps)): ?>
        <div style="color:#64748b;font-size:12px">No IPs currently blocked.</div>
        <?php else: ?>
        <table class="admin-table">
            <thead><tr><th>IP</th><th>Reason</th><th>Blocked At</th><th></th></tr></thead>
            <tbody>
            <?php foreach ($blockedIps as $bi): ?>
            <tr>
                <td class="fail-ip"><?= htmlspecialchars($bi['ip']) ?></td>
                <td style="color:#94a3b8;font-size:12px"><?= htmlspecialchars($bi['reason'] ?? '') ?></td>
                <td class="fail-time"><?= date('M j Y, g:i a', strtotime($bi['blocked_at'])) ?></td>
                <td>
                    <form method="post" style="margin:0">
                        <input type="hidden" name="unblock_ip" value="<?= htmlspecialchars($bi['ip']) ?>">
                        <button type="submit" class="btn-sm-action btn-unblock">Unblock</button>
                    </form>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php endif; ?>
    </div>

    <!-- ── Pending / Rejected users ── -->
    <?php if (!empty($pendingUsers)): ?>
    <div class="section-card">
        <div class="card-label label-pend">&#x23F3; Pending / Rejected Users</div>
        <table class="admin-table">
            <thead><tr><th>Email</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody>
            <?php foreach ($pendingUsers as $pu): ?>
            <tr>
                <td style="color:#d0d0d0"><?= htmlspecialchars($pu['email']) ?></td>
                <td>
                    <span class="badge-small <?= $pu['status']==='pending' ? 'badge-pending' : 'badge-reject' ?>">
                        <?= ucfirst($pu['status']) ?>
                    </span>
                </td>
                <td>
                    <form method="post" style="margin:0;display:inline">
                        <input type="hidden" name="approve_user" value="<?= htmlspecialchars($pu['email']) ?>">
                        <button type="submit" class="btn-sm-action btn-approve">Approve</button>
                    </form>
                    <form method="post" style="margin:0;display:inline">
                        <input type="hidden" name="reject_user" value="<?= htmlspecialchars($pu['email']) ?>">
                        <button type="submit" class="btn-sm-action btn-reject">Reject</button>
                    </form>
                </td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>

    <!-- ── Recent failed attempts ── -->
    <?php if (!empty($recentFails)): ?>
    <div class="section-card">
        <div class="card-label label-fails">&#x26A0; Recent Failed Login Attempts</div>
        <table class="admin-table">
            <thead><tr><th>Email</th><th>IP</th><th>Time</th></tr></thead>
            <tbody>
            <?php foreach ($recentFails as $f): ?>
            <tr>
                <td style="color:#d0d0d0"><?= htmlspecialchars($f['email']) ?></td>
                <td class="fail-ip"><?= htmlspecialchars($f['ip']) ?></td>
                <td class="fail-time"><?= date('M j, g:i a', strtotime($f['attempt_time'])) ?></td>
            </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>

    <!-- ── AI Security Audit ── -->
    <div class="section-card">
        <div class="card-label label-audit">&#x1F916; AI Security Audit</div>
        <p style="font-size:12px;color:#64748b;margin-bottom:12px">
            Ask Claude to audit the user-base security posture based on aggregate statistics.
        </p>
        <button class="btn-audit" id="audit-btn" onclick="runAudit()">
            &#x1F916; Run AI Security Audit
        </button>
        <div id="audit-result" style="margin-top:16px"></div>
    </div>

    <div class="back-link"><a href="homepage.php">&larr; Back to Dashboard</a></div>
</div>

<script>
async function runAudit() {
    const btn = document.getElementById('audit-btn');
    const res = document.getElementById('audit-result');
    btn.disabled = true;
    btn.textContent = 'Analysing…';
    res.textContent = '';
    try {
        const r    = await fetch('ai_password_audit.php');
        const data = await r.json();
        if (data.error) { res.textContent = 'Error: ' + data.error; return; }

        const a = data.audit || {};
        const s = data.stats || {};

        const gradeColor = {A:'#4ade80',B:'#86efac',C:'#facc15',D:'#fb923c',F:'#f87171'}[a.overall_grade] || '#94a3b8';

        let html = `<div style="display:flex;align-items:center;margin-bottom:14px">
            <div class="grade-badge" style="background:${gradeColor}22;color:${gradeColor};border:2px solid ${gradeColor}44">
                ${a.overall_grade || '?'}
            </div>
            <div>
                <div style="font-size:22px;font-weight:700;color:${gradeColor}">${a.overall_score || 0}/100</div>
                <div style="font-size:12px;color:#94a3b8">${escHtml(a.summary || '')}</div>
            </div>
        </div>`;

        html += `<div style="font-size:11px;color:#64748b;margin-bottom:12px">
            Users: ${s.total_users} &bull; With 2FA: ${s.pct_2fa}% &bull;
            Locked now: ${s.locked_now} &bull; Failed 7d: ${s.failed_total_7d}
        </div>`;

        if (a.issues && a.issues.length) {
            html += '<div style="font-weight:700;font-size:12px;color:#f87171;margin-bottom:6px">Issues</div>';
            a.issues.forEach(i => {
                const c = i.severity==='high' ? '#f87171' : i.severity==='medium' ? '#fb923c' : '#facc15';
                html += `<div style="font-size:12px;margin-bottom:5px">
                    <span style="color:${c};font-weight:700">[${(i.severity||'').toUpperCase()}]</span>
                    ${escHtml(i.description)}
                </div>`;
            });
        }

        if (a.recommendations && a.recommendations.length) {
            html += '<div style="font-weight:700;font-size:12px;color:#86efac;margin:10px 0 6px">Recommendations</div>';
            html += '<ol style="padding-left:18px;margin:0">';
            a.recommendations.forEach(r => { html += `<li style="font-size:12px;margin-bottom:4px">${escHtml(r)}</li>`; });
            html += '</ol>';
        }

        res.innerHTML = html;
    } catch (e) {
        res.textContent = 'Network error. Please try again.';
    } finally {
        btn.disabled    = false;
        btn.textContent = '&#x1F916; Re-run AI Security Audit';
        btn.innerHTML   = '&#x1F916; Re-run AI Security Audit';
    }
}

function escHtml(str) {
    const d = document.createElement('div');
    d.textContent = String(str);
    return d.innerHTML;
}
</script>
</body>
</html>
