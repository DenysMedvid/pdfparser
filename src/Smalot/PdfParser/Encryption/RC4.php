<?php

declare(strict_types=1);

namespace Smalot\PdfParser\Encryption;

/**
 * Pure-PHP RC4 stream cipher used by Standard Security Handler revisions
 * 2, 3, and 4 (when /CFM is /V2).
 *
 * RC4 is symmetric, so the same routine encrypts and decrypts.
 *
 * We intentionally do not call openssl_decrypt('rc4', ...): OpenSSL 3.x
 * disables RC4 by default (legacy provider only). The pure-PHP loop is
 * trivial and fast enough for PDF string/stream sizes.
 */
final class RC4
{
    public static function process(string $key, string $data): string
    {
        $keyLen = \strlen($key);
        if (0 === $keyLen) {
            return $data;
        }

        // Key-scheduling algorithm.
        $s = range(0, 255);
        $j = 0;
        for ($i = 0; $i < 256; ++$i) {
            $j = ($j + $s[$i] + \ord($key[$i % $keyLen])) & 0xFF;
            $tmp = $s[$i];
            $s[$i] = $s[$j];
            $s[$j] = $tmp;
        }

        // Pseudo-random generation algorithm.
        $i = 0;
        $j = 0;
        $out = '';
        $dataLen = \strlen($data);
        for ($n = 0; $n < $dataLen; ++$n) {
            $i = ($i + 1) & 0xFF;
            $j = ($j + $s[$i]) & 0xFF;
            $tmp = $s[$i];
            $s[$i] = $s[$j];
            $s[$j] = $tmp;
            $k = $s[($s[$i] + $s[$j]) & 0xFF];
            $out .= \chr(\ord($data[$n]) ^ $k);
        }

        return $out;
    }
}
