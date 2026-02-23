<?php
session_start();
$loginFailed = false;
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
</style>
</head>
<body>

<div class="container">
<div class="login-box">

<?php if ($loginFailed): ?>
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
</div>
<div class="form-group">
<label>Password</label>
<input type="password" name="password" id="reg-password" class="form-control" required>
<div id="pw-strength-bar"></div>
<div id="pw-strength-text"></div>
</div>
<button type="submit" class="btn btn-success"> SignUp </button>
</form>
</div>
</div>
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

/* ── 3. AI Login Failure Tips ── */
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
