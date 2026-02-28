<?php
session_start();

if (!isset($_SESSION['email'])) {
    header('location:login.php');
    exit();
}
?>
<!DOCTYPE html>
<html>
<head>
<title>Phishing Detector</title>
<link rel="stylesheet" type="text/css" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
<link rel="stylesheet" type="text/css" href="style/cleanup.css">
<style>
    h2 { color:#fff; text-align:center; margin-top:60px; text-transform:uppercase;
         font-size:1.35rem; letter-spacing:2px; }
    .pd-card {
        max-width:500px; margin:26px auto 0;
        background:rgba(255,255,255,0.07);
        border:1px solid rgba(255,255,255,0.13);
        border-radius:16px; padding:28px 32px;
        backdrop-filter:blur(8px);
    }
    .pd-intro {
        font-size:13px; color:#a0a0a0; line-height:1.6; margin-bottom:16px;
    }
    #pd-input {
        width:100%; border:1px solid rgba(255,255,255,0.18); border-radius:10px;
        padding:12px 14px; background:rgba(255,255,255,0.06);
        color:#fff; font-size:13px; outline:none; resize:vertical;
        min-height:120px; box-sizing:border-box;
    }
    #pd-input::placeholder { color:#444; }
    #pd-input:focus { border-color:#667eea; }
    #pd-btn {
        width:100%; margin-top:12px;
        background:linear-gradient(135deg,#667eea,#764ba2);
        border:none; border-radius:8px; color:#fff;
        padding:10px; font-size:14px; cursor:pointer; transition:opacity .2s;
    }
    #pd-btn:hover { opacity:0.85; }
    #pd-btn:disabled { opacity:0.45; cursor:not-allowed; }

    /* Result panel */
    #pd-result { display:none; margin-top:20px; }
    .pd-verdict-row {
        display:flex; align-items:center; gap:10px; margin-bottom:12px;
    }
    .pd-verdict-badge {
        font-size:16px; font-weight:700; padding:5px 14px;
        border-radius:20px; text-transform:uppercase; letter-spacing:1px;
    }
    .verdict-phishing   { background:rgba(239,68,68,0.2);  color:#fca5a5; border:1px solid rgba(239,68,68,0.4); }
    .verdict-suspicious { background:rgba(249,115,22,0.2); color:#fdba74; border:1px solid rgba(249,115,22,0.4); }
    .verdict-safe       { background:rgba(34,197,94,0.2);  color:#86efac; border:1px solid rgba(34,197,94,0.4); }
    .pd-confidence { font-size:12px; color:#888; }

    .pd-section-label {
        font-size:10px; font-weight:700; letter-spacing:1.2px;
        text-transform:uppercase; color:#94a3b8; margin:10px 0 5px;
    }
    .pd-reasons { padding-left:18px; margin:0; }
    .pd-reasons li { font-size:13px; color:#d0d0d0; margin-bottom:4px; line-height:1.5; }
    .pd-advice {
        font-size:13px; color:#c4b5fd; line-height:1.5;
        background:rgba(102,126,234,0.08);
        border:1px solid rgba(102,126,234,0.2);
        border-radius:8px; padding:10px 12px; margin-top:10px;
    }
    .pd-divider { border-color:rgba(255,255,255,0.08); margin:16px 0; }

    .back-link { text-align:center; margin-top:16px; }
    .back-link a { color:#a78bfa; font-size:13px; }
</style>
</head>
<body>
<h2>&#x1F3A3; Phishing Detector</h2>

<div class="pd-card">
    <div class="pd-intro">
        Paste a suspicious URL, email body, or text message below.
        AI will check it for phishing and scam indicators.
    </div>

    <textarea id="pd-input" placeholder="e.g.  https://paypa1-secure.com/verify  or paste the full email text…"></textarea>
    <button id="pd-btn">Analyse</button>

    <div id="pd-result">
        <hr class="pd-divider">
        <div class="pd-verdict-row">
            <span id="pd-verdict-badge" class="pd-verdict-badge"></span>
            <span id="pd-confidence" class="pd-confidence"></span>
        </div>
        <div class="pd-section-label">Observations</div>
        <ul id="pd-reasons" class="pd-reasons"></ul>
        <div id="pd-advice" class="pd-advice"></div>
    </div>

    <div class="back-link"><a href="homepage.php">&larr; Back to Dashboard</a></div>
</div>

<script>
(function () {
    const btn        = document.getElementById('pd-btn');
    const input      = document.getElementById('pd-input');
    const result     = document.getElementById('pd-result');
    const badge      = document.getElementById('pd-verdict-badge');
    const confidence = document.getElementById('pd-confidence');
    const reasons    = document.getElementById('pd-reasons');
    const advice     = document.getElementById('pd-advice');

    // Escape helper to prevent XSS from AI-returned text
    function esc(s) {
        const d = document.createElement('div');
        d.textContent = String(s);
        return d.innerHTML;
    }

    const verdictMeta = {
        phishing:   { cls:'verdict-phishing',   icon:'&#x1F6A8;', label:'Phishing' },
        suspicious: { cls:'verdict-suspicious',  icon:'&#x26A0;',  label:'Suspicious' },
        safe:       { cls:'verdict-safe',        icon:'&#x2705;',  label:'Safe' }
    };

    btn.addEventListener('click', async function () {
        const text = input.value.trim();
        if (!text) { input.focus(); return; }

        btn.disabled    = true;
        btn.textContent = 'Analysing\u2026';
        result.style.display = 'none';

        try {
            const res  = await fetch('ai_phishing.php', {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify({ text })
            });
            const data = await res.json();
            if (data.error) throw new Error(data.error);

            const verdict = (data.verdict || 'suspicious').toLowerCase();
            const meta    = verdictMeta[verdict] || verdictMeta['suspicious'];

            badge.className   = 'pd-verdict-badge ' + meta.cls;
            badge.innerHTML   = meta.icon + ' ' + meta.label;
            confidence.textContent = data.confidence
                ? data.confidence.charAt(0).toUpperCase() + data.confidence.slice(1) + ' confidence'
                : '';

            reasons.innerHTML = (data.reasons || [])
                .map(r => `<li>${esc(r)}</li>`).join('');

            advice.innerHTML = data.advice ? '&#x1F4A1; ' + esc(data.advice) : '';

            result.style.display = 'block';
        } catch (e) {
            alert('Analysis failed. Please try again.');
        } finally {
            btn.disabled    = false;
            btn.textContent = 'Analyse';
        }
    });

    // Allow Ctrl+Enter to submit
    input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' && e.ctrlKey) btn.click();
    });
})();
</script>
</body>
</html>
