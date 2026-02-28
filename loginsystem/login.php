<?php
session_start();
$loginFailed = false;
$lockedOut   = false;
if (!empty($_SESSION['lockout'])) {
    $lockedOut   = true;
    $loginFailed = true;
    unset($_SESSION['lockout']);
}
if (!empty($_SESSION['login_failed'])) {
    $loginFailed = true;
    unset($_SESSION['login_failed']);
}
?>
<!DOCTYPE html>
<html>
<head>
<title>User Login and Registration</title>
<link rel="stylesheet" type="text/css" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" type="text/css" href="style/cleanup.css">
<style>
    /* ── Password strength indicator ── */
    #pw-strength-bar {
        height:5px; border-radius:3px; margin-top:6px;
        background:#ddd; transition:background .4s, width .4s;
        width:0%;
    }
    #pw-strength-text {
        font-size:12px; margin-top:4px; min-height:16px; transition:color .3s;
    }
    .strength-weak        { background:#ef4444; width:25%; }
    .strength-fair        { background:#f97316; width:55%; }
    .strength-strong      { background:#22c55e; width:80%; }
    .strength-very-strong { background:#16a34a; width:100%; }

    /* ── Email validator indicator ── */
    #email-status {
        font-size:12px; margin-top:4px; min-height:16px;
        display:flex; align-items:center; gap:5px;
    }
    #email-status .badge-dot {
        width:8px; height:8px; border-radius:50%; flex-shrink:0;
    }

    /* ── Login-failed AI help panel ── */
    #ai-help-box {
        background:rgba(255,255,255,0.92); border-radius:10px;
        padding:14px 18px; margin-bottom:18px;
        border-left:4px solid #f97316; font-size:13px;
    }
    #ai-help-box strong { color:#b45309; }
    #ai-help-box ul { margin:8px 0 0 0; padding-left:18px; }
    #ai-help-box li { margin-bottom:4px; color:#374151; }
    #ai-help-box .ai-spinner { color:#888; font-style:italic; }
    #ai-help-close {
        float:right; background:none; border:none;
        font-size:16px; cursor:pointer; color:#aaa; line-height:1;
    }

    /* ── Username suggestion chips ── */
    #username-suggestions {
        display:flex; flex-wrap:wrap; gap:6px; margin-top:6px; min-height:0;
    }
    .uname-chip {
        background:rgba(102,126,234,0.12); border:1px solid rgba(102,126,234,0.4);
        border-radius:20px; padding:3px 11px; font-size:11px; color:#667eea;
        cursor:pointer; transition:background .2s; white-space:nowrap;
        user-select:none;
    }
    .uname-chip:hover { background:rgba(102,126,234,0.25); }

    /* ── Password generator button ── */
    #pw-gen-btn {
        display:inline-block; font-size:11px; color:#667eea;
        cursor:pointer; background:none; border:none; padding:0;
        text-decoration:underline; margin-top:4px;
    }
    #pw-gen-btn:disabled { color:#aaa; cursor:not-allowed; text-decoration:none; }

    /* ── FAQ mini-bot ── */
    #faq-toggle {
        position:fixed; bottom:28px; left:28px;
        width:44px; height:44px; border-radius:50%;
        background:rgba(255,255,255,0.12); border:1px solid rgba(255,255,255,0.25);
        cursor:pointer; box-shadow:0 3px 14px rgba(0,0,0,0.25);
        font-size:18px; color:#fff; z-index:1000;
        display:flex; align-items:center; justify-content:center;
        transition:transform .2s;
    }
    #faq-toggle:hover { transform:scale(1.1); }
    #faq-window {
        display:none; position:fixed; bottom:84px; left:28px;
        width:290px; background:#1e1e2e; border-radius:14px;
        box-shadow:0 8px 28px rgba(0,0,0,0.5); z-index:1000;
        border:1px solid rgba(255,255,255,0.08); overflow:hidden;
    }
    #faq-window.open { display:block; }
    #faq-header {
        padding:11px 14px;
        background:linear-gradient(135deg,#667eea,#764ba2);
        color:#fff; font-weight:600; font-size:13px;
        display:flex; align-items:center; justify-content:space-between;
    }
    #faq-header button { background:none; border:none; color:#fff; cursor:pointer; font-size:16px; line-height:1; }
    #faq-body { padding:13px; }
    #faq-answer {
        font-size:12px; color:#d0d0d0; line-height:1.6;
        min-height:36px; margin-bottom:10px;
    }
    #faq-answer.thinking { color:#666; font-style:italic; }
    #faq-input {
        width:100%; border:1px solid rgba(255,255,255,0.15); border-radius:8px;
        padding:7px 10px; background:rgba(255,255,255,0.05);
        color:#fff; font-size:12px; outline:none; box-sizing:border-box;
    }
    #faq-input::placeholder { color:#555; }
</style>
</head>
<body>

<div class="container">
<div class="login-box">

<?php if ($lockedOut): ?>
<!-- ── Account Lockout Banner ── -->
<div class="alert alert-danger py-2 mb-3" style="font-size:13px;border-radius:10px">
    <strong>&#x1F6AB; Account temporarily locked.</strong>
    Too many failed attempts. Please wait <strong>15 minutes</strong> before trying again.
</div>
<?php elseif ($loginFailed): ?>
<!-- ── AI Login Failure Help ── -->
<div id="ai-help-box">
    <button id="ai-help-close" title="Dismiss">&times;</button>
    <strong>&#x26A0; Login failed.</strong>
    <ul id="ai-tips-list">
        <li class="ai-spinner">Loading suggestions from AI…</li>
    </ul>
</div>
<?php endif; ?>

<div class="row">
<div class="col-md-6 signup-left">
<h2> Login Page</h2>
<form method="post" action="validation.php">
<div class="form-group">
<label>Username </label>
<input type="text" name="email" class="form-control" required>
</div>
<div class="form-group">
<label>Password</label>
<input type="password" name="password" class="form-control" required>
</div>
<button type="submit" class="btn btn-success"> SignIn </button>
</form>
</div>

<div class="col-md-6 signin-right">
<h2> Registration Page</h2>
<form method="post" action="config.php">
<div class="form-group">
<label>Username </label>
<input type="text" name="email" id="reg-email" class="form-control" required>
<div id="email-status"></div>
<div id="username-suggestions"></div>
</div>
<div class="form-group">
<label>Password</label>
<input type="password" name="password" id="reg-password" class="form-control" required>
<div id="pw-strength-bar"></div>
<div id="pw-strength-text"></div>
<button type="button" id="pw-gen-btn">&#x2728; Suggest a password</button>
</div>
<button type="submit" class="btn btn-success"> SignUp </button>
</form>
</div>
</div>
</div>
</div>

<!-- ── FAQ Mini-bot ── -->
<button id="faq-toggle" title="Quick Help">&#x2753;</button>
<div id="faq-window">
    <div id="faq-header">
        <span>Quick Help</span>
        <button id="faq-close">&times;</button>
    </div>
    <div id="faq-body">
        <div id="faq-answer">Ask me anything about logging in or registering!</div>
        <input id="faq-input" type="text" placeholder="Type your question…" maxlength="200" autocomplete="off">
    </div>
</div>

<script>
/* ── 1. AI Password Strength ── */
(function () {
    const pwInput = document.getElementById('reg-password');
    const bar     = document.getElementById('pw-strength-bar');
    const text    = document.getElementById('pw-strength-text');

    const colorMap = {
        'weak':        { cls:'strength-weak',        color:'#ef4444', label:'Weak' },
        'fair':        { cls:'strength-fair',        color:'#f97316', label:'Fair' },
        'strong':      { cls:'strength-strong',      color:'#22c55e', label:'Strong' },
        'very strong': { cls:'strength-very-strong', color:'#16a34a', label:'Very Strong' }
    };

    let timer = null;
    pwInput.addEventListener('input', function () {
        clearTimeout(timer);
        const val = this.value;
        if (!val) { bar.className=''; bar.style.width='0%'; text.textContent=''; return; }
        text.textContent = 'Analyzing…'; text.style.color = '#888';
        timer = setTimeout(() => checkStrength(val), 700);
    });

    async function checkStrength(password) {
        try {
            const res  = await fetch('ai_password.php', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({password}) });
            const data = await res.json();
            const key  = (data.strength||'').toLowerCase();
            const info = colorMap[key];
            bar.className = info ? info.cls : '';
            if (!info) bar.style.width = '0%';
            text.textContent = info ? info.label + ' — ' + data.message : data.message || '';
            text.style.color = info ? info.color : '#888';
        } catch (e) { text.textContent = ''; }
    }
})();

/* ── 2. AI Email Domain Validator ── */
(function () {
    const emailInput = document.getElementById('reg-email');
    const statusDiv  = document.getElementById('email-status');

    const config = {
        good:       { color:'#16a34a', icon:'✔' },
        suspicious: { color:'#f97316', icon:'⚠' },
        disposable: { color:'#ef4444', icon:'✖' },
        invalid:    { color:'#ef4444', icon:'✖' }
    };

    let timer = null;
    emailInput.addEventListener('input', function () {
        clearTimeout(timer);
        const val = this.value;
        if (!val || !val.includes('@')) { statusDiv.innerHTML = ''; return; }
        statusDiv.innerHTML = '<span style="color:#888;font-size:12px;font-style:italic">Checking email…</span>';
        timer = setTimeout(() => checkEmail(val), 800);
    });

    async function checkEmail(email) {
        try {
            const res  = await fetch('ai_email.php', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({email}) });
            const data = await res.json();
            if (!data.status) { statusDiv.innerHTML=''; return; }
            const cfg = config[data.status] || { color:'#888', icon:'?' };
            statusDiv.innerHTML =
                `<span class="badge-dot" style="background:${cfg.color}"></span>`
                + `<span style="color:${cfg.color};font-size:12px">${cfg.icon} ${data.message}</span>`;
        } catch (e) { statusDiv.innerHTML = ''; }
    }
})();

/* ── 3. AI Username Suggester ── */
(function () {
    const field   = document.getElementById('reg-email');
    const suggest = document.getElementById('username-suggestions');
    let timer = null;

    field.addEventListener('input', function () {
        clearTimeout(timer);
        suggest.innerHTML = '';
        const val = this.value;
        // Extract local part (before @) or use full value if no @
        const base = val.includes('@') ? val.split('@')[0] : val;
        if (base.length < 3) return;
        timer = setTimeout(() => fetchSuggestions(base, val), 1200);
    });

    async function fetchSuggestions(base, fullVal) {
        try {
            const res  = await fetch('ai_username.php', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username: base}) });
            const data = await res.json();
            if (!data.suggestions || !data.suggestions.length) return;
            const domain = fullVal.includes('@') ? '@' + fullVal.split('@')[1] : '';
            suggest.innerHTML = data.suggestions.map(s =>
                `<span class="uname-chip" data-val="${s}${domain}">${s}${domain}</span>`
            ).join('');
            suggest.querySelectorAll('.uname-chip').forEach(chip => {
                chip.addEventListener('click', () => { field.value = chip.dataset.val; suggest.innerHTML = ''; field.dispatchEvent(new Event('input')); });
            });
        } catch (e) { /* silent fail */ }
    }
})();

/* ── 4. AI Password Generator ── */
(function () {
    const btn   = document.getElementById('pw-gen-btn');
    const field = document.getElementById('reg-password');
    const text  = document.getElementById('pw-strength-text');

    btn.addEventListener('click', async function () {
        btn.disabled = true;
        btn.textContent = 'Generating…';
        try {
            const res  = await fetch('ai_passgen.php');
            const data = await res.json();
            if (data.password) {
                field.type  = 'text';
                field.value = data.password;
                text.textContent  = 'Generated — copy it somewhere safe, then it will hide.';
                text.style.color  = '#667eea';
                setTimeout(() => { field.type = 'password'; }, 5000);
                // Trigger strength check
                field.dispatchEvent(new Event('input'));
            }
        } catch (e) {
            text.textContent = 'Could not generate. Try again.';
        } finally {
            btn.disabled    = false;
            btn.textContent = '✨ Suggest a password';
        }
    });
})();

/* ── 5. FAQ Mini-bot ── */
(function () {
    const toggle  = document.getElementById('faq-toggle');
    const win     = document.getElementById('faq-window');
    const close   = document.getElementById('faq-close');
    const answerEl = document.getElementById('faq-answer');
    const input   = document.getElementById('faq-input');

    toggle.addEventListener('click', () => { win.classList.toggle('open'); if (win.classList.contains('open')) input.focus(); });
    close.addEventListener('click',  () => win.classList.remove('open'));

    input.addEventListener('keydown', async function (e) {
        if (e.key !== 'Enter') return;
        const q = input.value.trim();
        if (!q) return;
        input.value = '';
        answerEl.className = 'thinking';
        answerEl.textContent = 'Thinking…';
        try {
            const res  = await fetch('ai_faq.php', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({question: q}) });
            const data = await res.json();
            answerEl.className = '';
            answerEl.textContent = data.answer || 'Sorry, no answer available.';
        } catch (e) {
            answerEl.className = '';
            answerEl.textContent = 'Network error. Please try again.';
        }
    });
})();

/* ── 6. AI Login Failure Tips ── */
<?php if ($loginFailed): ?>
(async function () {
    const list  = document.getElementById('ai-tips-list');
    const close = document.getElementById('ai-help-close');
    close.addEventListener('click', () => document.getElementById('ai-help-box').remove());

    try {
        const res  = await fetch('ai_login_help.php');
        const data = await res.json();
        if (data.tips && data.tips.length) {
            list.innerHTML = data.tips.map(t => `<li>${t}</li>`).join('');
        }
    } catch (e) {
        list.innerHTML = '<li>Check your email and password, then try again.</li>';
    }
})();
<?php endif; ?>
</script>
</body>
</html>
