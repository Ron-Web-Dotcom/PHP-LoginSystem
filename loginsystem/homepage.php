<?php
session_start();

if (!isset($_SESSION['email'])) {
    header('location:login.php');
    exit();
}
?>
<html>
<head>
<title>Dashboard</title>
<link rel="stylesheet" type="text/css" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" type="text/css" href="style/cleanup.css">
<style>
    a { color:#fff !important; margin-top:-200px; }
    h1 { color:#fff !important; margin-top:200px !important; text-align:center; text-transform:uppercase; }

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
</style>
</head>
<body>
<a href="logout.php">LOGOUT</a>
<h1>Welcome <?php echo htmlspecialchars($_SESSION['email']); ?></h1>

<!-- ── AI Security Tip Card ── -->
<div id="tip-card">
    <div class="tip-icon">&#x1F512;</div>
    <div class="tip-label">Security Tip of the Session</div>
    <div id="tip-text" class="loading">Fetching your tip…</div>
</div>

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
</script>
</body>
</html>
