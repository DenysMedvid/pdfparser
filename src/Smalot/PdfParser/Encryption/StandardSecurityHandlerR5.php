<?php

declare(strict_types=1);

namespace Smalot\PdfParser\Encryption;

use Smalot\PdfParser\Exception\EncryptionException;
use Smalot\PdfParser\Exception\IncorrectPasswordException;

/**
 * Standard Security Handler revision 5 — the deprecated Acrobat 9 /
 * "ExtensionLevel 3" draft of AES-256. Superseded by R=6 in PDF 2.0;
 * still encountered in the wild from files produced 2008-2012.
 *
 * Differences from R=6: validation hash is one SHA-256 of
 * (password ‖ salt) rather than the iterated Algorithm 2.B used by R=6.
 * Otherwise identical: no per-object key, AES-256-CBC for all
 * streams/strings with a 16-byte leading IV.
 */
final class StandardSecurityHandlerR5 implements StandardSecurityHandler
{
    /** @var string 32-byte file encryption key. */
    private $fileKey;

    public function __construct(array $encryptDict, string $fileId, string $password)
    {
        // $fileId is unused for R=5/6 — kept in the signature to match
        // the other handlers' shape and document the convention.
        unset($fileId);

        $u = $encryptDict['U'] ?? '';
        $ue = $encryptDict['UE'] ?? '';
        if (\strlen($u) < 48) {
            throw new EncryptionException('/U entry must be >= 48 bytes for R=5 (got '.\strlen($u).')');
        }
        if (32 !== \strlen($ue)) {
            throw new EncryptionException('/UE entry must be 32 bytes for R=5 (got '.\strlen($ue).')');
        }

        $passwordBytes = self::truncatePassword($password);
        $validationSalt = substr($u, 32, 8);
        $keySalt = substr($u, 40, 8);

        // Validation hash = SHA-256(password ‖ validation_salt).
        $expectedHash = substr($u, 0, 32);
        $actualHash = hash('sha256', $passwordBytes.$validationSalt, true);
        if (!hash_equals($expectedHash, $actualHash)) {
            throw new IncorrectPasswordException(
                'Password does not unlock this PDF (Standard handler R=5).'
            );
        }

        // File key = AES-256-CBC(key = SHA-256(password ‖ key_salt),
        //                       iv  = 16 zero bytes,
        //                       no padding) applied to /UE.
        $intermediate = hash('sha256', $passwordBytes.$keySalt, true);
        $plain = openssl_decrypt(
            $ue,
            'aes-256-cbc',
            $intermediate,
            \OPENSSL_RAW_DATA | \OPENSSL_ZERO_PADDING,
            str_repeat("\x00", 16)
        );
        if (false === $plain || 32 !== \strlen($plain)) {
            throw new EncryptionException('Failed to derive R=5 file key: '.openssl_error_string());
        }

        $this->fileKey = $plain;
    }

    public function decryptBytes(string $ciphertext, string $objRef): string
    {
        // $objRef is unused — R=5/6 have no per-object key derivation.
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
     * Truncate the password to its first 127 bytes per ISO 32000-1
     * ExtensionLevel 3. The R=6 SASLprep step does not apply here.
     */
    private static function truncatePassword(string $password): string
    {
        return substr($password, 0, 127);
    }
}
