<?php
/**
 * Shared authentication gate.
 * Include at the top of any page that requires a logged-in user.
 * Handles session-based auth and "remember me" persistent cookies.
 */
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

if (!isset($_SESSION['email'])) {
    _auth_try_remember_cookie();
}

if (!isset($_SESSION['email'])) {
    header('location:login.php');
    exit();
}

function _auth_try_remember_cookie(): void
{
    if (empty($_COOKIE['remember_token'])) return;

    // Cookie format: "email:hex_token"
    $sep = strpos($_COOKIE['remember_token'], ':');
    if ($sep === false) return;

    $cookieEmail = substr($_COOKIE['remember_token'], 0, $sep);
    $rawToken    = substr($_COOKIE['remember_token'], $sep + 1);
    if ($cookieEmail === '' || $rawToken === '') return;

    $email     = substr($cookieEmail, 0, 255);
    $tokenHash = hash('sha256', $rawToken);
    $now       = date('Y-m-d H:i:s');

    $con = mysqli_connect('localhost', 'root', '', 'system');
    if (!$con) return;

    $tcheck = mysqli_query($con, "SHOW TABLES LIKE 'tbl_remember_tokens'");
    if (!$tcheck || mysqli_num_rows($tcheck) === 0) {
        mysqli_close($con);
        return;
    }

    $stmt = mysqli_prepare($con,
        "SELECT email FROM tbl_remember_tokens
         WHERE email = ? AND token_hash = ? AND expires_at > ?"
    );
    mysqli_stmt_bind_param($stmt, 'sss', $email, $tokenHash, $now);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_bind_result($stmt, $foundEmail);
    $found = mysqli_stmt_fetch($stmt);
    mysqli_stmt_close($stmt);

    // Check IP blocklist before restoring session from cookie
    $currentIp = $_SERVER['REMOTE_ADDR'] ?? '';
    $tblBl = mysqli_query($con, "SHOW TABLES LIKE 'tbl_ip_blocklist'");
    if ($tblBl && mysqli_num_rows($tblBl) > 0) {
        $blSt = mysqli_prepare($con, "SELECT 1 FROM tbl_ip_blocklist WHERE ip = ?");
        if ($blSt) {
            mysqli_stmt_bind_param($blSt, 's', $currentIp);
            mysqli_stmt_execute($blSt);
            mysqli_stmt_store_result($blSt);
            $ipIsBlocked = mysqli_stmt_num_rows($blSt) > 0;
            mysqli_stmt_close($blSt);
            if ($ipIsBlocked) {
                mysqli_close($con);
                session_destroy();
                header('location:login.php');
                exit();
            }
        }
    }

    // Pull is_admin and role so the session is complete
    $isAdmin = 0;
    $role    = 'user';
    if ($found) {
        $s2 = mysqli_prepare($con, "SELECT is_admin, role FROM tbl_signup WHERE email = ?");
        if ($s2) {
            mysqli_stmt_bind_param($s2, 's', $foundEmail);
            mysqli_stmt_execute($s2);
            mysqli_stmt_bind_result($s2, $isAdmin, $role);
            mysqli_stmt_fetch($s2);
            mysqli_stmt_close($s2);
        }
        $_SESSION['email']    = $foundEmail;
        $_SESSION['is_admin'] = (int) $isAdmin;
        $_SESSION['role']     = $role ?? 'user';
        // Slide the cookie expiry window
        setcookie(
            'remember_token',
            $_COOKIE['remember_token'],
            time() + 30 * 86400,
            '/', '', false, true
        );
    }

    mysqli_close($con);
}
