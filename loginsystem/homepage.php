<?php
require_once 'auth_check.php';   // session_start + remember-me cookie

// Fetch last 5 logins for the session-activity card
$recentLogins = [];
$_con = mysqli_connect('localhost', 'root', '', 'system');
if ($_con) {
    $tcheck = mysqli_query($_con, "SHOW TABLES LIKE 'tbl_session_log'");
    if ($tcheck && mysqli_num_rows($tcheck) > 0) {
        $_s = mysqli_prepare($_con,
            "SELECT ip, login_time FROM tbl_session_log WHERE email = ? ORDER BY login_time DESC LIMIT 5"
        );
        mysqli_stmt_bind_param($_s, 's', $_SESSION['email']);
        mysqli_stmt_execute($_s);
        $_r = mysqli_stmt_get_result($_s);
        while ($row = mysqli_fetch_assoc($_r)) { $recentLogins[] = $row; }
        mysqli_stmt_close($_s);
    }
    mysqli_close($_con);
}
$isAdmin    = !empty($_SESSION['is_admin']);
$newIpAlert = $_SESSION['new_ip_alert'] ?? null;
if ($newIpAlert) unset($_SESSION['new_ip_alert']);
?>
<html>
<head>
<title>Dashboard</title>
<link rel="stylesheet" type="text/css" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" type="text/css" href="style/cleanup.css">
<style>
    a { color:#fff !important; margin-top:-200px; }
    h1 { color:#fff !important; margin-top:70px !important; text-align:center; text-transform:uppercase; }
    .dash-links { text-align:center; margin-top:10px; flex-wrap:wrap; display:flex; justify-content:center; gap:4px 14px; }
    .dash-links a { font-size:13px; color:#a78bfa !important; }

    /* ── New IP alert banner ── */
    #new-ip-banner {
        max-width:480px; margin:14px auto 0;
        background:rgba(251,146,60,0.12); border:1px solid rgba(251,146,60,0.35);
        border-radius:12px; padding:12px 16px;
        color:#fdba74; font-size:13px; display:flex; align-items:center; gap:10px;
    }
    #new-ip-banner .niab-close {
        margin-left:auto; background:none; border:none;
        color:#fb923c; font-size:16px; cursor:pointer; line-height:1;
    }

    /* ── Notification bell ── */
    #notif-bell {
        position:fixed; top:18px; right:66px;
        background:rgba(255,255,255,0.1); border:1px solid rgba(255,255,255,0.2);
        border-radius:50%; width:38px; height:38px; font-size:18px;
        cursor:pointer; color:#fff; z-index:500;
        display:flex; align-items:center; justify-content:center;
        transition:background .2s;
    }
    #notif-bell:hover { background:rgba(255,255,255,0.2); }
    #notif-badge {
        position:absolute; top:-4px; right:-4px;
        background:#ef4444; color:#fff; border-radius:50%;
        width:16px; height:16px; font-size:10px; font-weight:700;
        display:flex; align-items:center; justify-content:center;
        display:none;
    }
    #notif-dropdown {
        display:none; position:fixed; top:62px; right:66px;
        width:300px; background:#1e1e2e; border-radius:14px;
        box-shadow:0 8px 28px rgba(0,0,0,0.5); z-index:501;
        border:1px solid rgba(255,255,255,0.08); overflow:hidden;
    }
    #notif-dropdown.open { display:block; }
    .notif-header {
        padding:10px 14px; background:linear-gradient(135deg,#667eea,#764ba2);
        color:#fff; font-weight:600; font-size:13px;
        display:flex; align-items:center; justify-content:space-between;
    }
    .notif-header button { background:none;border:none;color:#fff;font-size:11px;cursor:pointer; }
    .notif-list { max-height:280px; overflow-y:auto; }
    .notif-item {
        padding:10px 14px; border-bottom:1px solid rgba(255,255,255,0.05);
        font-size:12px; color:#d0d0d0; line-height:1.5;
    }
    .notif-item:last-child { border-bottom:none; }
    .notif-item.unread { background:rgba(102,126,234,0.06); }
    .notif-time { font-size:10px; color:#64748b; margin-top:2px; }
    .notif-type-warning { border-left:3px solid #fb923c; }
    .notif-type-danger  { border-left:3px solid #ef4444; }
    .notif-type-success { border-left:3px solid #4ade80; }
    .notif-type-info    { border-left:3px solid #60a5fa; }
    .notif-empty { padding:16px; text-align:center; color:#64748b; font-size:12px; }

    /* ── AI Anomaly card ── */
    #anomaly-card {
        max-width:480px; margin:14px auto 0;
        background:rgba(139,92,246,0.07); border:1px solid rgba(139,92,246,0.2);
        border-radius:14px; padding:18px 24px; color:#e0e0e0; backdrop-filter:blur(6px);
    }
    #anomaly-card .anom-label {
        font-size:11px; font-weight:700; letter-spacing:1.5px;
        text-transform:uppercase; color:#a78bfa; margin-bottom:10px;
    }
    .btn-anom {
        background:rgba(139,92,246,0.2); border:1px solid rgba(139,92,246,0.35);
        color:#c4b5fd; border-radius:8px; padding:6px 14px;
        font-size:12px; cursor:pointer; transition:background .15s;
    }
    .btn-anom:hover { background:rgba(139,92,246,0.35); }
    .anom-row {
        display:flex; align-items:flex-start; gap:8px;
        padding:7px 0; border-bottom:1px solid rgba(255,255,255,0.05); font-size:12px;
    }
    .anom-row:last-child { border-bottom:none; }
    .sev-high   { color:#f87171; }
    .sev-medium { color:#fb923c; }
    .sev-low    { color:#facc15; }

    /* ── Keyboard shortcuts modal ── */
    #kb-modal {
        display:none; position:fixed; inset:0;
        background:rgba(0,0,0,0.6); z-index:600;
        align-items:center; justify-content:center;
    }
    #kb-modal.open { display:flex; }
    #kb-box {
        background:#1e1e2e; border-radius:16px; padding:24px 28px;
        border:1px solid rgba(255,255,255,0.1); min-width:280px;
        box-shadow:0 10px 40px rgba(0,0,0,0.6);
    }
    #kb-box h4 { color:#fff; font-size:14px; margin-bottom:14px; }
    .kb-row { display:flex; align-items:center; gap:10px; margin-bottom:8px; font-size:13px; color:#d0d0d0; }
    .kb-key {
        background:rgba(255,255,255,0.1); border:1px solid rgba(255,255,255,0.2);
        border-radius:6px; padding:2px 8px; font-family:monospace; font-size:12px; color:#fff;
        min-width:26px; text-align:center;
    }

    /* ── Geo tag in session log ── */
    .log-geo { font-size:11px; color:#64748b; text-align:center; }

    /* ── Theme toggle ── */
    #theme-toggle {
        position:fixed; top:18px; right:20px;
        background:rgba(255,255,255,0.1); border:1px solid rgba(255,255,255,0.2);
        border-radius:50%; width:38px; height:38px; font-size:18px;
        cursor:pointer; color:#fff; z-index:500;
        display:flex; align-items:center; justify-content:center;
        transition:background .2s;
    }
    #theme-toggle:hover { background:rgba(255,255,255,0.2); }

    /* ── Chat widget ── */
    #chat-toggle {
        position:fixed; bottom:28px; right:28px;
        width:56px; height:56px; border-radius:50%;
        background:linear-gradient(135deg,#667eea,#764ba2);
        border:none; cursor:pointer; box-shadow:0 4px 18px rgba(0,0,0,0.35);
        font-size:24px; color:#fff; z-index:1000;
        display:flex; align-items:center; justify-content:center;
        transition:transform .2s;
    }
    #chat-toggle:hover { transform:scale(1.1); }
    #chat-window {
        display:none; position:fixed; bottom:96px; right:28px;
        width:340px; max-height:480px;
        background:#1e1e2e; border-radius:16px;
        box-shadow:0 8px 32px rgba(0,0,0,0.5);
        flex-direction:column; overflow:hidden; z-index:1000;
        border:1px solid rgba(255,255,255,0.08);
    }
    #chat-window.open { display:flex; }
    #chat-header {
        padding:14px 16px;
        background:linear-gradient(135deg,#667eea,#764ba2);
        color:#fff; font-weight:600; font-size:14px;
        display:flex; align-items:center; gap:8px;
    }
    #chat-header span.dot { width:8px; height:8px; border-radius:50%; background:#4ade80; display:inline-block; }
    #chat-messages {
        flex:1; overflow-y:auto; padding:14px;
        display:flex; flex-direction:column; gap:10px;
        scrollbar-width:thin; scrollbar-color:rgba(255,255,255,0.2) transparent;
    }
    .msg { max-width:82%; font-size:13px; line-height:1.5; word-break:break-word; }
    .msg.user {
        align-self:flex-end;
        background:linear-gradient(135deg,#667eea,#764ba2);
        color:#fff; border-radius:14px 14px 2px 14px; padding:9px 13px;
    }
    .msg.bot {
        align-self:flex-start;
        background:rgba(255,255,255,0.08); color:#e0e0e0;
        border-radius:14px 14px 14px 2px; padding:9px 13px;
    }
    .msg.bot.thinking { color:#888; font-style:italic; }
    #chat-input-row {
        display:flex; padding:10px; gap:8px;
        border-top:1px solid rgba(255,255,255,0.08); background:#1e1e2e;
    }
    #chat-input {
        flex:1; border:1px solid rgba(255,255,255,0.15); border-radius:10px;
        padding:8px 12px; background:rgba(255,255,255,0.05);
        color:#fff; font-size:13px; outline:none; resize:none; height:38px;
    }
    #chat-input::placeholder { color:#666; }
    #chat-send {
        background:linear-gradient(135deg,#667eea,#764ba2);
        border:none; border-radius:10px; color:#fff;
        padding:0 14px; cursor:pointer; font-size:16px; transition:opacity .2s;
    }
    #chat-send:hover { opacity:0.85; }
    #chat-send:disabled { opacity:0.4; cursor:not-allowed; }

    /* ── Security score card ── */
    #score-card {
        max-width:480px; margin:24px auto 0;
        background:rgba(255,255,255,0.07);
        border:1px solid rgba(255,255,255,0.12);
        border-radius:14px; padding:18px 24px;
        color:#e0e0e0; backdrop-filter:blur(6px);
    }
    #score-card .score-label {
        font-size:11px; font-weight:700; letter-spacing:1.5px;
        text-transform:uppercase; color:#a78bfa; margin-bottom:10px;
    }
    .score-header { display:flex; align-items:center; gap:14px; margin-bottom:8px; }
    .score-grade  { font-size:40px; font-weight:800; line-height:1; }
    .score-meta   { flex:1; }
    .score-value  { font-size:22px; font-weight:700; }
    .score-summary { font-size:13px; color:#94a3b8; margin-top:2px; }
    .score-recs   { padding-left:18px; margin:8px 0 0; }
    .score-recs li { font-size:12px; color:#9ca3af; margin-bottom:3px; line-height:1.5; }

    /* ── Security tip card ── */
    #tip-card {
        max-width:480px; margin:14px auto 0;
        background:rgba(255,255,255,0.08);
        border:1px solid rgba(255,255,255,0.15);
        border-radius:14px; padding:20px 24px;
        text-align:center; color:#e0e0e0; backdrop-filter:blur(6px);
    }
    #tip-card .tip-label {
        font-size:11px; font-weight:700; letter-spacing:1.5px;
        text-transform:uppercase; color:#a78bfa; margin-bottom:8px;
    }
    #tip-card .tip-icon { font-size:22px; margin-bottom:6px; }
    #tip-card #tip-text { font-size:14px; line-height:1.6; }
    #tip-card #tip-text.loading { color:#666; font-style:italic; }

    /* ── Threat briefing card ── */
    #threat-card {
        max-width:480px; margin:14px auto 0;
        background:rgba(239,68,68,0.07);
        border:1px solid rgba(239,68,68,0.25);
        border-radius:14px; padding:18px 24px;
        color:#e0e0e0; backdrop-filter:blur(6px);
    }
    #threat-card .threat-label {
        font-size:11px; font-weight:700; letter-spacing:1.5px;
        text-transform:uppercase; color:#f87171; margin-bottom:6px;
    }
    #threat-card .threat-name { font-size:15px; font-weight:700; color:#fca5a5; margin-bottom:4px; }
    #threat-card .threat-desc { font-size:13px; line-height:1.5; margin-bottom:6px; }
    #threat-card .threat-tip  { font-size:12px; color:#86efac; }

    /* ── Quiz card ── */
    #quiz-card {
        max-width:480px; margin:14px auto 0;
        background:rgba(255,255,255,0.07);
        border:1px solid rgba(255,255,255,0.14);
        border-radius:14px; padding:20px 24px;
        color:#e0e0e0; backdrop-filter:blur(6px); text-align:center;
    }
    #quiz-card .quiz-label {
        font-size:11px; font-weight:700; letter-spacing:1.5px;
        text-transform:uppercase; color:#34d399; margin-bottom:10px;
    }
    #quiz-start-btn {
        background:linear-gradient(135deg,#34d399,#059669);
        border:none; border-radius:8px; color:#fff;
        padding:8px 22px; font-size:13px; cursor:pointer; transition:opacity .2s;
    }
    #quiz-start-btn:hover { opacity:0.85; }
    #quiz-start-btn:disabled { opacity:0.45; cursor:not-allowed; }
    #quiz-body { display:none; text-align:left; margin-top:12px; }
    #quiz-question { font-size:14px; font-weight:600; color:#f0f0f0; margin-bottom:12px; line-height:1.5; }
    .quiz-opt {
        display:block; width:100%; text-align:left;
        background:rgba(255,255,255,0.06); border:1px solid rgba(255,255,255,0.14);
        border-radius:8px; padding:8px 12px; color:#d0d0d0; font-size:13px;
        cursor:pointer; margin-bottom:7px; transition:background .15s;
    }
    .quiz-opt:hover:not(:disabled) { background:rgba(255,255,255,0.12); }
    .quiz-opt.correct { background:rgba(34,197,94,0.2); border-color:#22c55e; color:#86efac; }
    .quiz-opt.wrong   { background:rgba(239,68,68,0.2);  border-color:#ef4444; color:#fca5a5; }
    #quiz-result { font-size:13px; margin-top:10px; line-height:1.5; min-height:18px; }
    #quiz-next-btn {
        display:none; margin-top:12px;
        background:none; border:1px solid rgba(52,211,153,0.4);
        border-radius:8px; color:#34d399;
        padding:6px 18px; font-size:13px; cursor:pointer; transition:background .2s;
    }
    #quiz-next-btn:hover { background:rgba(52,211,153,0.1); }

    /* ── Session activity log card ── */
    #session-log-card {
        max-width:480px; margin:14px auto 40px;
        background:rgba(255,255,255,0.05);
        border:1px solid rgba(255,255,255,0.1);
        border-radius:14px; padding:18px 24px;
        color:#e0e0e0; backdrop-filter:blur(6px);
    }
    #session-log-card .log-label {
        font-size:11px; font-weight:700; letter-spacing:1.5px;
        text-transform:uppercase; color:#60a5fa; margin-bottom:10px;
    }
    .log-table { width:100%; border-collapse:collapse; font-size:12px; }
    .log-table td { padding:6px 4px; border-bottom:1px solid rgba(255,255,255,0.06); }
    .log-table tr:last-child td { border-bottom:none; }
    .log-time { color:#94a3b8; }
    .log-ip   { color:#64748b; font-family:monospace; text-align:right; }
    .log-current { color:#86efac; font-weight:600; }

    /* ── Light mode overrides ── */
    body.light-mode h1    { color:#1a1a2e !important; }
    body.light-mode a     { color:#1a1a2e !important; }
    body.light-mode .dash-links a { color:#5b21b6 !important; }
    body.light-mode #theme-toggle { background:rgba(0,0,0,0.08); border-color:rgba(0,0,0,0.15); color:#1a1a2e; }
    body.light-mode #score-card,
    body.light-mode #tip-card,
    body.light-mode #quiz-card,
    body.light-mode #session-log-card {
        background:rgba(255,255,255,0.88); border-color:rgba(0,0,0,0.1); color:#374151;
    }
    body.light-mode #threat-card { background:rgba(239,68,68,0.05); border-color:rgba(239,68,68,0.2); }
    body.light-mode #tip-card .tip-label  { color:#7c3aed; }
    body.light-mode #quiz-card .quiz-label { color:#059669; }
    body.light-mode .quiz-opt { background:#f9fafb; border-color:rgba(0,0,0,0.12); color:#374151; }
    body.light-mode .quiz-opt:hover:not(:disabled) { background:#e0e7ff; }
    body.light-mode #quiz-question { color:#1f2937; }
    body.light-mode .score-summary { color:#6b7280; }
    body.light-mode .score-recs li { color:#6b7280; }
    body.light-mode .log-time { color:#4b5563; }
    body.light-mode .log-ip   { color:#6b7280; }
    body.light-mode #chat-window { background:#f8fafc; border-color:rgba(0,0,0,0.1); }
    body.light-mode #chat-input-row { background:#f8fafc; border-color:rgba(0,0,0,0.1); }
    body.light-mode #chat-input { background:rgba(0,0,0,0.04); border-color:rgba(0,0,0,0.15); color:#1a1a2e; }
    body.light-mode #chat-input::placeholder { color:#9ca3af; }
    body.light-mode .msg.bot { background:rgba(0,0,0,0.06); color:#1f2937; }
</style>
</head>
<body>

<!-- Theme toggle button -->
<button id="theme-toggle" title="Toggle light/dark mode">&#x1F319;</button>

<!-- Notification bell -->
<div style="position:fixed;top:18px;right:66px;z-index:500">
    <button id="notif-bell" title="Notifications">
        &#x1F514;
        <span id="notif-badge"></span>
    </button>
    <div id="notif-dropdown">
        <div class="notif-header">
            <span>&#x1F514; Notifications</span>
            <button id="notif-mark-read" title="Mark all read">Mark all read</button>
        </div>
        <div class="notif-list" id="notif-list">
            <div class="notif-empty">Loading…</div>
        </div>
    </div>
</div>

<!-- Keyboard shortcuts modal -->
<div id="kb-modal">
    <div id="kb-box">
        <h4>&#x2328; Keyboard Shortcuts</h4>
        <div class="kb-row"><span class="kb-key">p</span> Open Profile</div>
        <div class="kb-row"><span class="kb-key">2</span> 2FA Setup</div>
        <div class="kb-row"><span class="kb-key">k</span> Change Password</div>
        <div class="kb-row"><span class="kb-key">a</span> Admin Panel <?php if (!$isAdmin): echo '(admin only)'; endif; ?></div>
        <div class="kb-row"><span class="kb-key">s</span> Security Report</div>
        <div class="kb-row"><span class="kb-key">l</span> Logout</div>
        <div class="kb-row"><span class="kb-key">?</span> Toggle this help</div>
        <div class="kb-row"><span class="kb-key">Esc</span> Close overlays</div>
        <div style="text-align:center;margin-top:12px">
            <button onclick="document.getElementById('kb-modal').classList.remove('open')"
                    style="background:rgba(255,255,255,0.1);border:1px solid rgba(255,255,255,0.2);border-radius:8px;color:#fff;padding:5px 16px;font-size:12px;cursor:pointer">
                Close
            </button>
        </div>
    </div>
</div>

<a href="logout.php">LOGOUT</a>
<h1>Welcome <?php echo htmlspecialchars($_SESSION['email']); ?></h1>

<?php if ($newIpAlert): ?>
<!-- New IP alert banner -->
<div id="new-ip-banner">
    <span>&#x26A0; Login detected from a new IP address. Previous logins were from <strong><?= htmlspecialchars($newIpAlert) ?></strong>. If this wasn't you, change your password immediately.</span>
    <button class="niab-close" onclick="this.parentElement.remove()">&times;</button>
</div>
<?php endif; ?>

<div class="dash-links">
    <a href="profile.php">&#x1F464; Profile</a>
    <a href="totp_setup.php">&#x1F510; 2FA Setup</a>
    <a href="backup_codes.php">&#x1F5DD; Backup Codes</a>
    <a href="change_password.php">&#x1F511; Change Password</a>
    <a href="session_manager.php">&#x1F5A5; Sessions</a>
    <a href="audit_log.php">&#x1F4DC; Audit Log</a>
    <a href="onboarding.php">&#x2705; Setup Checklist</a>
    <a href="security_report.php">&#x1F4CB; Security Report</a>
    <a href="phishing.php">&#x1F3A3; Phishing Detector</a>
    <a href="export_log.php">&#x1F4E5; Export Log</a>
    <?php if ($isAdmin): ?>
    <a href="admin.php" style="color:#f97316 !important">&#x1F6E1; Admin</a>
    <?php endif; ?>
</div>

<!-- AI Anomaly Detector (on-demand) -->
<div id="anomaly-card">
    <div class="anom-label">&#x1F9EC; AI Anomaly Detector</div>
    <p style="font-size:12px;color:#64748b;margin-bottom:10px">
        Analyse your login patterns for unusual behaviour.
    </p>
    <button class="btn-anom" id="anom-btn" onclick="runAnomalyCheck()">
        &#x1F50D; Analyse My Login Patterns
    </button>
    <div id="anom-result" style="margin-top:12px"></div>
</div>

<!-- ── AI Security Score Card ── -->
<div id="score-card">
    <div class="score-label">&#x1F6E1; Account Security Score</div>
    <div id="score-inner" style="color:#555;font-style:italic;font-size:13px">Calculating…</div>
</div>

<!-- ── AI Security Tip Card ── -->
<div id="tip-card">
    <div class="tip-icon">&#x1F512;</div>
    <div class="tip-label">Security Tip of the Session</div>
    <div id="tip-text" class="loading">Fetching your tip…</div>
</div>

<!-- ── AI Threat Briefing Card ── -->
<div id="threat-card">
    <div class="threat-label">&#x26A0; Threat of the Session</div>
    <div id="threat-inner" style="color:#555;font-style:italic;font-size:13px">Loading…</div>
</div>

<!-- ── AI Security Quiz Card ── -->
<div id="quiz-card">
    <div class="quiz-label">&#x1F9E0; Security Quiz</div>
    <button id="quiz-start-btn">Take a Question</button>
    <div id="quiz-body">
        <div id="quiz-question"></div>
        <div id="quiz-options"></div>
        <div id="quiz-result"></div>
        <button id="quiz-next-btn">Next Question &rarr;</button>
    </div>
</div>

<!-- ── Session Activity Log ── -->
<?php if (!empty($recentLogins)): ?>
<div id="session-log-card">
    <div class="log-label">&#x1F4CB; Recent Login Activity</div>
    <table class="log-table">
        <?php foreach ($recentLogins as $i => $login): ?>
        <tr>
            <td class="<?php echo $i === 0 ? 'log-current' : 'log-time'; ?>">
                <?php
                if ($i === 0) echo '&#x25CF; Current session';
                else echo htmlspecialchars(date('M j, g:i a', strtotime($login['login_time'])));
                ?>
            </td>
            <td class="log-ip"><?php echo htmlspecialchars($login['ip']); ?></td>
        </tr>
        <?php endforeach; ?>
    </table>
</div>
<?php endif; ?>

<!-- ── AI Chat Toggle Button ── -->
<button id="chat-toggle" title="Ask AI">&#x1F916;</button>

<!-- ── AI Chat Window ── -->
<div id="chat-window">
    <div id="chat-header">
        <span class="dot"></span> AI Assistant
    </div>
    <div id="chat-messages">
        <div class="msg bot">Hi <?php echo htmlspecialchars(explode('@', $_SESSION['email'])[0]); ?>! How can I help you today?</div>
    </div>
    <div id="chat-input-row">
        <input id="chat-input" placeholder="Type a message…" autocomplete="off" maxlength="1000">
        <button id="chat-send">&#x27A4;</button>
    </div>
</div>

<script>
/* ── 0a. Notification bell ── */
(function () {
    const bell     = document.getElementById('notif-bell');
    const dropdown = document.getElementById('notif-dropdown');
    const badge    = document.getElementById('notif-badge');
    const list     = document.getElementById('notif-list');
    const markRead = document.getElementById('notif-mark-read');
    const typeIcon = {warning:'⚠️',danger:'🔴',success:'✅',info:'ℹ️'};

    async function load() {
        try {
            const r = await fetch('get_notifications.php');
            const d = await r.json();
            if (d.unread > 0) {
                badge.textContent = d.unread > 9 ? '9+' : d.unread;
                badge.style.display = 'flex';
            } else {
                badge.style.display = 'none';
            }
            if (!d.notifications || !d.notifications.length) {
                list.innerHTML = '<div class="notif-empty">No notifications</div>';
                return;
            }
            list.innerHTML = d.notifications.map(n =>
                `<div class="notif-item ${n.is_read ? '' : 'unread'} notif-type-${n.type}">
                    <div>${typeIcon[n.type] || '•'} ${escHtmlNotif(n.message)}</div>
                    <div class="notif-time">${escHtmlNotif(n.time_ago)}</div>
                </div>`
            ).join('');
        } catch (e) {}
    }

    function escHtmlNotif(s) {
        const d = document.createElement('div'); d.textContent = String(s); return d.innerHTML;
    }

    bell.addEventListener('click', function (e) {
        e.stopPropagation();
        dropdown.classList.toggle('open');
        if (dropdown.classList.contains('open')) load();
    });

    markRead.addEventListener('click', async function () {
        await fetch('mark_notifications_read.php', { method:'POST' });
        badge.style.display = 'none';
        list.querySelectorAll('.notif-item').forEach(i => i.classList.remove('unread'));
    });

    document.addEventListener('click', function (e) {
        if (!dropdown.contains(e.target) && e.target !== bell) {
            dropdown.classList.remove('open');
        }
    });

    load();   // initial badge count
})();

/* ── 0b. Keyboard shortcuts ── */
(function () {
    const isAdmin = <?= $isAdmin ? 'true' : 'false' ?>;
    document.addEventListener('keydown', function (e) {
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
        const kbModal = document.getElementById('kb-modal');
        switch (e.key) {
            case '?': kbModal.classList.toggle('open'); break;
            case 'Escape':
                kbModal.classList.remove('open');
                document.getElementById('notif-dropdown').classList.remove('open');
                const cw = document.getElementById('chat-window');
                if (cw) cw.classList.remove('open');
                break;
            case 'p': window.location = 'profile.php';        break;
            case '2': window.location = 'totp_setup.php';     break;
            case 'k': window.location = 'change_password.php'; break;
            case 's': window.location = 'security_report.php'; break;
            case 'l': window.location = 'logout.php';          break;
            case 'a': if (isAdmin) window.location = 'admin.php'; break;
        }
    });
})();

/* ── 0c. AI Anomaly Detector ── */
async function runAnomalyCheck() {
    const btn = document.getElementById('anom-btn');
    const res = document.getElementById('anom-result');
    btn.disabled = true;
    btn.textContent = 'Analysing…';
    res.innerHTML = '';
    function esc(s) { const d=document.createElement('div');d.textContent=String(s);return d.innerHTML; }
    try {
        const r = await fetch('ai_anomaly.php', { method:'POST' });
        const d = await r.json();
        if (d.error) { res.textContent = d.error; return; }
        let html = `<div style="font-size:12px;color:#94a3b8;margin-bottom:8px">${esc(d.summary || '')}</div>`;
        if (d.anomalies && d.anomalies.length) {
            d.anomalies.forEach(a => {
                const cls = a.severity === 'high' ? 'sev-high' : a.severity === 'medium' ? 'sev-medium' : 'sev-low';
                html += `<div class="anom-row">
                    <span class="${cls}" style="font-weight:700;flex-shrink:0">[${esc((a.severity||'').toUpperCase())}]</span>
                    <span>${esc(a.description)}</span>
                </div>`;
            });
        } else {
            html += '<div style="color:#4ade80;font-size:12px">✅ No anomalies detected — your login patterns look normal.</div>';
        }
        res.innerHTML = html;
    } catch (e) {
        res.textContent = 'Network error.';
    } finally {
        btn.disabled    = false;
        btn.textContent = '🔍 Re-analyse';
    }
}

/* ── 0d. Geolocation on session log IPs ── */
(function () {
    document.querySelectorAll('.log-ip').forEach(async cell => {
        const ip = cell.textContent.trim();
        if (!ip || ip.startsWith('127.') || ip.startsWith('::') || ip === '0.0.0.0') return;
        try {
            const r = await fetch('get_geo.php?ip=' + encodeURIComponent(ip));
            const d = await r.json();
            if (d.flag || d.city) {
                const tag = document.createElement('div');
                tag.className = 'log-geo';
                tag.textContent = [d.flag, d.city, d.country].filter(Boolean).join(' ');
                cell.parentNode.insertBefore(tag, cell.nextSibling);
            }
        } catch (e) {}
    });
})();

/* ── 0. Theme toggle ── */
(function () {
    const btn  = document.getElementById('theme-toggle');
    const body = document.body;
    const DARK_ICON  = '\u{1F319}';  // moon
    const LIGHT_ICON = '\u2600\uFE0F'; // sun

    if (localStorage.getItem('theme') === 'light') {
        body.classList.add('light-mode');
        btn.textContent = LIGHT_ICON;
    } else {
        btn.textContent = DARK_ICON;
    }

    btn.addEventListener('click', function () {
        body.classList.toggle('light-mode');
        const light = body.classList.contains('light-mode');
        localStorage.setItem('theme', light ? 'light' : 'dark');
        this.textContent = light ? LIGHT_ICON : DARK_ICON;
    });
})();

/* ── 1. AI Security Score ── */
(async function () {
    const inner = document.getElementById('score-inner');
    function esc(s) { const d = document.createElement('div'); d.textContent = String(s); return d.innerHTML; }
    try {
        const res  = await fetch('ai_security_score.php');
        const data = await res.json();
        if (data.error) { inner.textContent = 'Score unavailable.'; return; }

        const color = data.color || '#94a3b8';
        const recs  = (data.recommendations || [])
            .map(r => `<li>${esc(r)}</li>`).join('');
        inner.style.fontStyle = 'normal';
        inner.innerHTML =
            `<div class="score-header">
                <div class="score-grade" style="color:${color}">${esc(data.grade)}</div>
                <div class="score-meta">
                    <div class="score-value" style="color:${color}">${esc(data.score)}<span style="font-size:14px;color:#64748b">/100</span></div>
                    <div class="score-summary">${esc(data.summary || '')}</div>
                </div>
            </div>
            ${recs ? '<ul class="score-recs">' + recs + '</ul>' : ''}`;
    } catch (e) {
        inner.textContent = '';
    }
})();

/* ── 2. Chat widget ── */
(function () {
    const toggle   = document.getElementById('chat-toggle');
    const win      = document.getElementById('chat-window');
    const messages = document.getElementById('chat-messages');
    const input    = document.getElementById('chat-input');
    const sendBtn  = document.getElementById('chat-send');

    toggle.addEventListener('click', () => {
        win.classList.toggle('open');
        if (win.classList.contains('open')) input.focus();
    });

    function addMsg(text, role) {
        const div = document.createElement('div');
        div.className = 'msg ' + role;
        div.textContent = text;
        messages.appendChild(div);
        messages.scrollTop = messages.scrollHeight;
        return div;
    }

    async function send() {
        const text = input.value.trim();
        if (!text) return;
        input.value = '';
        sendBtn.disabled = true;
        addMsg(text, 'user');
        const thinking = addMsg('Thinking…', 'bot thinking');
        try {
            const res = await fetch('ai_chat.php', {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: text })
            });
            const data = await res.json();
            thinking.remove();
            addMsg(data.reply || data.error || 'Something went wrong.', 'bot');
        } catch (e) {
            thinking.remove();
            addMsg('Network error. Please try again.', 'bot');
        } finally {
            sendBtn.disabled = false;
            input.focus();
        }
    }

    sendBtn.addEventListener('click', send);
    input.addEventListener('keydown', e => {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
    });
})();

/* ── 3. AI Security Tip ── */
(async function () {
    const tipEl = document.getElementById('tip-text');
    try {
        const res  = await fetch('ai_tip.php');
        if (res.status === 401) { tipEl.textContent = ''; return; }
        const data = await res.json();
        tipEl.classList.remove('loading');
        tipEl.textContent = data.tip || '';
    } catch (e) { tipEl.textContent = ''; }
})();

/* ── 4. AI Threat Briefing ── */
(async function () {
    const inner = document.getElementById('threat-inner');
    function esc(s) { const d = document.createElement('div'); d.textContent = String(s); return d.innerHTML; }
    try {
        const res  = await fetch('ai_threat.php');
        if (res.status === 401) { inner.textContent = ''; return; }
        const data = await res.json();
        inner.style.cssText = 'font-style:normal';
        inner.innerHTML =
            `<div class="threat-name">${esc(data.threat)}</div>`
          + `<div class="threat-desc">${esc(data.description)}</div>`
          + `<div class="threat-tip">&#x1F6E1; ${esc(data.tip)}</div>`;
    } catch (e) { inner.textContent = ''; }
})();

/* ── 5. AI Security Quiz ── */
(function () {
    const startBtn   = document.getElementById('quiz-start-btn');
    const body       = document.getElementById('quiz-body');
    const questionEl = document.getElementById('quiz-question');
    const optionsEl  = document.getElementById('quiz-options');
    const resultEl   = document.getElementById('quiz-result');
    const nextBtn    = document.getElementById('quiz-next-btn');

    async function loadQuestion() {
        startBtn.disabled    = true;
        startBtn.textContent = 'Loading…';
        body.style.display   = 'none';
        optionsEl.innerHTML  = '';
        resultEl.textContent = '';
        nextBtn.style.display= 'none';
        try {
            const res  = await fetch('ai_quiz.php');
            const data = await res.json();
            if (data.error) throw new Error(data.error);
            questionEl.textContent = data.question;
            optionsEl.innerHTML = data.options.map((opt, i) =>
                `<button class="quiz-opt" data-i="${i}">${opt}</button>`
            ).join('');
            optionsEl.querySelectorAll('.quiz-opt').forEach(btn => {
                btn.addEventListener('click', function () {
                    const chosen = parseInt(this.dataset.i);
                    optionsEl.querySelectorAll('.quiz-opt').forEach(b => b.disabled = true);
                    if (chosen === data.answer) {
                        this.classList.add('correct');
                        resultEl.textContent = '✔ Correct! ' + data.explanation;
                        resultEl.style.color = '#86efac';
                    } else {
                        this.classList.add('wrong');
                        optionsEl.querySelector(`[data-i="${data.answer}"]`).classList.add('correct');
                        resultEl.textContent = '✖ Not quite. ' + data.explanation;
                        resultEl.style.color = '#fca5a5';
                    }
                    nextBtn.style.display = 'inline-block';
                });
            });
            body.style.display     = 'block';
            startBtn.style.display = 'none';
        } catch (e) {
            startBtn.textContent = 'Try Again';
            startBtn.disabled    = false;
        }
    }

    startBtn.addEventListener('click', loadQuestion);
    nextBtn.addEventListener('click', () => {
        startBtn.style.display = 'inline-block';
        startBtn.textContent   = 'Next Question';
        loadQuestion();
    });
})();
</script>
</body>
</html>
