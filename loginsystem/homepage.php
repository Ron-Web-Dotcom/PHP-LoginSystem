<?php
session_start();

if (!isset($_SESSION['email'])) {
    header('location:login.php');
    exit();
}

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
?>
<html>
<head>
<title>Dashboard</title>
<link rel="stylesheet" type="text/css" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" type="text/css" href="style/cleanup.css">
<style>
    a { color:#fff !important; margin-top:-200px; }
    h1 { color:#fff !important; margin-top:80px !important; text-align:center; text-transform:uppercase; }
    .dash-links { text-align:center; margin-top:10px; }
    .dash-links a { font-size:13px; color:#a78bfa !important; margin:0 10px; }

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
    #chat-header span.dot {
        width:8px; height:8px; border-radius:50%;
        background:#4ade80; display:inline-block;
    }

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
        border-top:1px solid rgba(255,255,255,0.08);
        background:#1e1e2e;
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
        padding:0 14px; cursor:pointer; font-size:16px;
        transition:opacity .2s;
    }
    #chat-send:hover { opacity:0.85; }
    #chat-send:disabled { opacity:0.4; cursor:not-allowed; }

    /* ── Security tip card ── */
    #tip-card {
        max-width:480px; margin:24px auto 0;
        background:rgba(255,255,255,0.08);
        border:1px solid rgba(255,255,255,0.15);
        border-radius:14px; padding:20px 24px;
        text-align:center; color:#e0e0e0;
        backdrop-filter:blur(6px);
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
    #threat-card.loading      { color:#555; font-style:italic; }

    /* ── Quiz card ── */
    #quiz-card {
        max-width:480px; margin:14px auto 0;
        background:rgba(255,255,255,0.07);
        border:1px solid rgba(255,255,255,0.14);
        border-radius:14px; padding:20px 24px;
        color:#e0e0e0; backdrop-filter:blur(6px);
        text-align:center;
    }
    #quiz-card .quiz-label {
        font-size:11px; font-weight:700; letter-spacing:1.5px;
        text-transform:uppercase; color:#34d399; margin-bottom:10px;
    }
    #quiz-start-btn {
        background:linear-gradient(135deg,#34d399,#059669);
        border:none; border-radius:8px; color:#fff;
        padding:8px 22px; font-size:13px; cursor:pointer;
        transition:opacity .2s;
    }
    #quiz-start-btn:hover { opacity:0.85; }
    #quiz-start-btn:disabled { opacity:0.45; cursor:not-allowed; }
    #quiz-body { display:none; text-align:left; margin-top:12px; }
    #quiz-question { font-size:14px; font-weight:600; color:#f0f0f0; margin-bottom:12px; line-height:1.5; }
    .quiz-opt {
        display:block; width:100%; text-align:left;
        background:rgba(255,255,255,0.06);
        border:1px solid rgba(255,255,255,0.14);
        border-radius:8px; padding:8px 12px;
        color:#d0d0d0; font-size:13px; cursor:pointer;
        margin-bottom:7px; transition:background .15s;
    }
    .quiz-opt:hover:not(:disabled) { background:rgba(255,255,255,0.12); }
    .quiz-opt.correct { background:rgba(34,197,94,0.2); border-color:#22c55e; color:#86efac; }
    .quiz-opt.wrong   { background:rgba(239,68,68,0.2);  border-color:#ef4444; color:#fca5a5; }
    #quiz-result { font-size:13px; margin-top:10px; line-height:1.5; min-height:18px; }
    #quiz-next-btn {
        display:none; margin-top:12px;
        background:none; border:1px solid rgba(52,211,153,0.4);
        border-radius:8px; color:#34d399;
        padding:6px 18px; font-size:13px; cursor:pointer;
        transition:background .2s;
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
</style>
</head>
<body>
<a href="logout.php">LOGOUT</a>
<h1>Welcome <?php echo htmlspecialchars($_SESSION['email']); ?></h1>
<div class="dash-links">
    <a href="change_password.php">&#x1F511; Change Password</a>
    <a href="phishing.php">&#x1F3A3; Phishing Detector</a>
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
                if ($i === 0) {
                    echo '&#x25CF; Current session';
                } else {
                    echo htmlspecialchars(date('M j, g:i a', strtotime($login['login_time'])));
                }
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
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
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

/* ── AI Security Tip ── */
(async function () {
    const tipEl = document.getElementById('tip-text');
    try {
        const res  = await fetch('ai_tip.php');
        if (res.status === 401) { tipEl.textContent = ''; return; }
        const data = await res.json();
        tipEl.classList.remove('loading');
        tipEl.textContent = data.tip || '';
    } catch (e) {
        tipEl.textContent = '';
    }
})();

/* ── AI Threat Briefing ── */
(async function () {
    const inner = document.getElementById('threat-inner');
    try {
        const res  = await fetch('ai_threat.php');
        if (res.status === 401) { inner.textContent = ''; return; }
        const data = await res.json();
        inner.style.cssText = 'font-style:normal';
        inner.innerHTML =
            `<div class="threat-name">${data.threat}</div>`
          + `<div class="threat-desc">${data.description}</div>`
          + `<div class="threat-tip">&#x1F6E1; ${data.tip}</div>`;
    } catch (e) {
        inner.textContent = '';
    }
})();

/* ── AI Security Quiz ── */
(function () {
    const startBtn  = document.getElementById('quiz-start-btn');
    const body      = document.getElementById('quiz-body');
    const questionEl= document.getElementById('quiz-question');
    const optionsEl = document.getElementById('quiz-options');
    const resultEl  = document.getElementById('quiz-result');
    const nextBtn   = document.getElementById('quiz-next-btn');

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
                        resultEl.textContent  = '✔ Correct! ' + data.explanation;
                        resultEl.style.color  = '#86efac';
                    } else {
                        this.classList.add('wrong');
                        optionsEl.querySelector(`[data-i="${data.answer}"]`).classList.add('correct');
                        resultEl.textContent  = '✖ Not quite. ' + data.explanation;
                        resultEl.style.color  = '#fca5a5';
                    }
                    nextBtn.style.display = 'inline-block';
                });
            });

            body.style.display   = 'block';
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
