<?php
/**
 * Minimal RFC 6238 TOTP implementation.
 * Compatible with Google Authenticator, Authy, and any standard TOTP app.
 */

function totp_generate_secret(): string
{
    $chars  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $secret = '';
    for ($i = 0; $i < 16; $i++) {
        $secret .= $chars[random_int(0, 31)];
    }
    return $secret;
}

function _totp_base32_decode(string $secret): string
{
    $chars  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $secret = strtoupper(preg_replace('/[^A-Z2-7]/i', '', $secret));
    $bits   = '';
    foreach (str_split($secret) as $char) {
        $pos = strpos($chars, $char);
        if ($pos !== false) {
            $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }
    }
    $output = '';
    foreach (str_split($bits, 8) as $chunk) {
        if (strlen($chunk) === 8) {
            $output .= chr(bindec($chunk));
        }
    }
    return $output;
}

function totp_code(string $secret, int $time = 0): string
{
    if ($time === 0) $time = time();
    $step    = (int) floor($time / 30);
    $counter = pack('N', 0) . pack('N', $step);   // 8-byte big-endian
    $key     = _totp_base32_decode($secret);
    $hash    = hash_hmac('sha1', $counter, $key, true);
    $offset  = ord($hash[19]) & 0x0f;
    $code    = (
        ((ord($hash[$offset])     & 0x7f) << 24) |
        ((ord($hash[$offset + 1]) & 0xff) << 16) |
        ((ord($hash[$offset + 2]) & 0xff) <<  8) |
         (ord($hash[$offset + 3]) & 0xff)
    ) % 1000000;
    return str_pad((string) $code, 6, '0', STR_PAD_LEFT);
}

function totp_verify(string $secret, string $code): bool
{
    if (!preg_match('/^\d{6}$/', $code)) return false;
    // Allow ±1 time window to handle minor clock skew
    for ($drift = -1; $drift <= 1; $drift++) {
        if (hash_equals(totp_code($secret, time() + $drift * 30), $code)) {
            return true;
        }
    }
    return false;
}

function totp_qr_url(string $email, string $secret): string
{
    $label   = rawurlencode('PHP-LoginSystem:' . $email);
    $otpauth = "otpauth://totp/{$label}?secret={$secret}&issuer=PHP-LoginSystem&digits=6&period=30";
    return 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' . rawurlencode($otpauth);
}
