
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
</style>
</head>
<body>

<div class="container">

<div class="login-box">
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
<input type="text" name="email" class="form-control" required>
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
(function () {
    const pwInput  = document.getElementById('reg-password');
    const bar      = document.getElementById('pw-strength-bar');
    const text     = document.getElementById('pw-strength-text');

    const colorMap = {
        'weak':        { cls: 'strength-weak',        color: '#ef4444', label: 'Weak' },
        'fair':        { cls: 'strength-fair',        color: '#f97316', label: 'Fair' },
        'strong':      { cls: 'strength-strong',      color: '#22c55e', label: 'Strong' },
        'very strong': { cls: 'strength-very-strong', color: '#16a34a', label: 'Very Strong' }
    };

    let debounceTimer = null;

    pwInput.addEventListener('input', function () {
        clearTimeout(debounceTimer);

        const val = this.value;

        if (val.length === 0) {
            bar.className = '';
            bar.style.width = '0%';
            text.textContent = '';
            return;
        }

        text.textContent  = 'Analyzing…';
        text.style.color  = '#888';

        debounceTimer = setTimeout(() => checkStrength(val), 700);
    });

    async function checkStrength(password) {
        try {
            const res  = await fetch('ai_password.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password })
            });
            const data = await res.json();

            const key  = (data.strength || '').toLowerCase();
            const info = colorMap[key];

            bar.className = info ? info.cls : '';
            if (!info) bar.style.width = '0%';
            text.textContent = info ? info.label + ' — ' + data.message : data.message || '';
            text.style.color = info ? info.color : '#888';
        } catch (e) {
            text.textContent = '';
        }
    }
})();
</script>
</body>
</html>
