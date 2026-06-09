<?php

declare(strict_types=1);

namespace Smalot\PdfParser\Encryption;

use Smalot\PdfParser\Exception\EncryptionException;
use Smalot\PdfParser\Exception\IncorrectPasswordException;

/**
 * Standard Security Handler revision 6 — PDF 2.0 (ISO 32000-2 §7.6.4).
 *
 * The visible cipher is the same as R=5 (AES-256-CBC for every string
 * and stream, no per-object key derivation). The difference lives in
 * how the file encryption key is recovered from the password: R=6
 * replaces R=5's single SHA-256 with the iterated Algorithm 2.B that
 * cycles between SHA-256/384/512 and AES-128-CBC for at least 64
 * rounds, with a data-dependent termination check.
 *
 * SASLprep (RFC 4013) on the password is a no-op for the empty
 * password and is therefore skipped — non-empty passwords are
 * rejected at the SecurityHandler dispatcher.
 */
final class StandardSecurityHandlerR6 implements StandardSecurityHandler
{
    /** @var string 32-byte file encryption key. */
    private $fileKey;

    public function __construct(array $encryptDict, string $fileId, string $password)
    {
        unset($fileId);

        $u = $encryptDict['U'] ?? '';
        $ue = $encryptDict['UE'] ?? '';
        if (\strlen($u) < 48) {
            throw new EncryptionException('/U entry must be >= 48 bytes for R=6 (got '.\strlen($u).')');
        }
        if (32 !== \strlen($ue)) {
            throw new EncryptionException('/UE entry must be 32 bytes for R=6 (got '.\strlen($ue).')');
        }

        $passwordBytes = self::truncatePassword($password);
        $validationSalt = substr($u, 32, 8);
        $keySalt = substr($u, 40, 8);

        $expectedHash = substr($u, 0, 32);
        $actualHash = self::algorithm2B($passwordBytes, $validationSalt, '');
        if (!hash_equals($expectedHash, $actualHash)) {
            throw new IncorrectPasswordException(
                'Password does not unlock this PDF (Standard handler R=6).'
            );
        }

        $intermediate = self::algorithm2B($passwordBytes, $keySalt, '');
        $plain = openssl_decrypt(
            $ue,
            'aes-256-cbc',
            $intermediate,
            \OPENSSL_RAW_DATA | \OPENSSL_ZERO_PADDING,
            str_repeat("\x00", 16)
        );
        if (false === $plain || 32 !== \strlen($plain)) {
            throw new EncryptionException('Failed to derive R=6 file key: '.openssl_error_string());
        }

        $this->fileKey = $plain;
    }

    public function decryptBytes(string $ciphertext, string $objRef): string
    {
        unset($objRef);

        if (\strlen($ciphertext) < 16) {
            throw new EncryptionException('AES-256 input too short to contain an IV.');
        }
        $iv = substr($ciphertext, 0, 16);
        $body = substr($ciphertext, 16);

        $plain = openssl_decrypt($body, 'aes-256-cbc', $this->fileKey, \OPENSSL_RAW_DATA, $iv);
        if (false === $plain) {
            throw new EncryptionException('AES-256-CBC decrypt failed: '.openssl_error_string());
        }

        return $plain;
    }

    /**
     * Algorithm 2.B (ISO 32000-2 §7.6.4.3.3) — iterated password hash.
     *
     * Runs at least 64 rounds. Each round encrypts a 64×-repeated
     * (password ‖ K ‖ userKey) block under AES-128-CBC keyed on the
     * current 32-byte K, then rehashes the ciphertext with SHA-256,
     * SHA-384, or SHA-512 selected by the sum of the first 16 bytes
     * of ciphertext modulo 3. Terminates when (round ≥ 64) and the
     * last byte of ciphertext ≤ (round − 32).
     */
    private static function algorithm2B(string $password, string $salt, string $userKey): string
    {
        $k = hash('sha256', $password.$salt.$userKey, true);
        $round = 0;

        $hashAlgo = ['sha256', 'sha384', 'sha512'];

        while (true) {
            $block = $password.$k.$userKey;
            $k1 = str_repeat($block, 64);

            $aesKey = substr($k, 0, 16);
            $aesIv = substr($k, 16, 16);

            $e = openssl_encrypt(
                $k1,
                'aes-128-cbc',
                $aesKey,
                \OPENSSL_RAW_DATA | \OPENSSL_ZERO_PADDING,
                $aesIv
            );
            if (false === $e) {
                throw new EncryptionException(
                    'Algorithm 2.B AES-128-CBC encrypt failed: '.openssl_error_string()
                );
            }

            // Sum of first 16 ciphertext bytes mod 3 selects the hash.
            $sum = 0;
            for ($i = 0; $i < 16; ++$i) {
                $sum += \ord($e[$i]);
            }
            $k = hash($hashAlgo[$sum % 3], $e, true);

            ++$round;
            if ($round >= 64 && \ord($e[\strlen($e) - 1]) <= $round - 32) {
                break;
            }
        }

        return substr($k, 0, 32);
    }

    private static function truncatePassword(string $password): string
    {
        return substr($password, 0, 127);
    }
}
