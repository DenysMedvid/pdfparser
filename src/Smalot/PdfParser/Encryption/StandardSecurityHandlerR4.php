<?php

declare(strict_types=1);

namespace Smalot\PdfParser\Encryption;

use Smalot\PdfParser\Exception\EncryptionException;
use Smalot\PdfParser\Exception\IncorrectPasswordException;
use Smalot\PdfParser\Exception\UnsupportedSecurityHandlerException;

/**
 * Standard Security Handler revisions 2, 3, and 4 (ISO 32000-1 §7.6.3).
 *
 * R=2: RC4 with 40-bit key (Acrobat 3).
 * R=3: RC4 with 40..128-bit key (Acrobat 5).
 * R=4: RC4 or AES-128 selected via the crypt-filter table (Acrobat 7).
 *
 * For R=4 we only support the configuration where /StmF and /StrF
 * reference the same crypt filter — split filter configurations are
 * rare in practice and explicitly out of scope.
 */
final class StandardSecurityHandlerR4 implements StandardSecurityHandler
{
    /** The 32-byte padding constant from Algorithm 2 step (a). */
    private const PADDING = "\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A";

    /** @var int Revision (2, 3, or 4). */
    private $revision;

    /** @var bool Whether streams/strings use AES-128 (true) or RC4 (false). */
    private $useAes;

    /** @var string Derived file-encryption key, length 5..16 bytes. */
    private $fileKey;

    /**
     * @param array  $encryptDict Normalized /Encrypt dictionary.
     * @param string $fileId      Raw bytes of the trailer's /ID[0].
     * @param string $password    User-supplied password (we only accept "").
     */
    public function __construct(array $encryptDict, string $fileId, string $password)
    {
        $this->revision = (int) ($encryptDict['R'] ?? 0);
        if ($this->revision < 2 || $this->revision > 4) {
            throw new UnsupportedSecurityHandlerException(
                'StandardSecurityHandlerR4 only handles R=2/3/4, got R='.$this->revision
            );
        }

        $this->useAes = self::resolveUseAes($encryptDict);

        $this->fileKey = $this->computeFileKey($password, $encryptDict, $fileId);

        if (!$this->authenticateUserPassword($password, $encryptDict, $fileId)) {
            throw new IncorrectPasswordException(
                'Password does not unlock this PDF (Standard handler R='.$this->revision.').'
            );
        }
    }

    public function decryptBytes(string $ciphertext, string $objRef): string
    {
        [$objNum, $genNum] = self::splitObjRef($objRef);
        $objKey = $this->deriveObjectKey($objNum, $genNum);

        if ($this->useAes) {
            return self::aes128CbcDecrypt($objKey, $ciphertext);
        }

        return RC4::process($objKey, $ciphertext);
    }

    /**
     * Algorithm 2 — compute the file encryption key from a password.
     *
     * @param string $password    Plain-text password (may be empty).
     * @param array  $encryptDict Normalized /Encrypt dict (provides O, P, Length, EncryptMetadata).
     * @param string $fileId      Raw bytes of /ID[0] from the trailer.
     */
    private function computeFileKey(string $password, array $encryptDict, string $fileId): string
    {
        $padded = self::padPassword($password);

        $o = $encryptDict['O'] ?? '';
        if (32 !== \strlen($o)) {
            throw new EncryptionException('/O entry must be 32 bytes (got '.\strlen($o).')');
        }

        // P is a signed 32-bit integer. Encode as little-endian 4 bytes.
        $p = (int) ($encryptDict['P'] ?? 0);
        $pBytes = pack('V', $p & 0xFFFFFFFF);

        $material = $padded.$o.$pBytes.$fileId;

        // R=4 with /EncryptMetadata false appends 0xFFFFFFFF to step (f).
        if (4 === $this->revision && false === ($encryptDict['EncryptMetadata'] ?? true)) {
            $material .= "\xFF\xFF\xFF\xFF";
        }

        $keyLenBytes = $this->keyLengthBytes($encryptDict);

        $hash = md5($material, true);

        // R>=3: rehash 50 times, truncating to keyLenBytes each iteration.
        if ($this->revision >= 3) {
            for ($i = 0; $i < 50; ++$i) {
                $hash = md5(substr($hash, 0, $keyLenBytes), true);
            }
        }

        return substr($hash, 0, $keyLenBytes);
    }

    /**
     * Algorithms 4 (R=2) and 5 (R>=3) — confirm we derived the right
     * file key by reproducing the writer's /U value.
     */
    private function authenticateUserPassword(string $password, array $encryptDict, string $fileId): bool
    {
        $u = $encryptDict['U'] ?? '';
        if (32 !== \strlen($u)) {
            return false;
        }

        if (2 === $this->revision) {
            // Algorithm 4: U = RC4(fileKey, padding).
            $computed = RC4::process($this->fileKey, self::PADDING);

            return hash_equals($u, $computed);
        }

        // Algorithm 5: U = RC4(fileKey ⊕ k=0..19, MD5(padding || ID)) || 16 zero bytes.
        $seed = md5(self::PADDING.$fileId, true);
        $enc = RC4::process($this->fileKey, $seed);
        for ($k = 1; $k <= 19; ++$k) {
            $xorKey = self::xorByteWise($this->fileKey, \chr($k));
            $enc = RC4::process($xorKey, $enc);
        }

        // Only the first 16 bytes of /U are checked; the remaining 16 are
        // arbitrary salt bytes added at encryption time.
        return hash_equals(substr($u, 0, 16), substr($enc, 0, 16));
    }

    /**
     * Per-object key derivation (Algorithm 1):
     *   k_obj = MD5(fileKey ‖ objNum_LE3 ‖ genNum_LE2 [‖ "sAlT"])
     *   truncated to min(fileKeyLen + 5, 16) bytes.
     */
    private function deriveObjectKey(int $objNum, int $genNum): string
    {
        $material = $this->fileKey
            .substr(pack('V', $objNum), 0, 3)
            .substr(pack('V', $genNum), 0, 2);

        if ($this->useAes) {
            // PDF spec literal — note: ASCII 0x73 0x41 0x6C 0x54.
            $material .= 'sAlT';
        }

        $hash = md5($material, true);
        $keyLen = min(\strlen($this->fileKey) + 5, 16);

        return substr($hash, 0, $keyLen);
    }

    /**
     * AES-128-CBC decrypt of a string or stream body. PDF spec requires
     * the first 16 bytes to be the IV.
     */
    private static function aes128CbcDecrypt(string $key, string $ciphertext): string
    {
        if (\strlen($ciphertext) < 16) {
            throw new EncryptionException('AES-128 input too short to contain an IV.');
        }
        $iv = substr($ciphertext, 0, 16);
        $body = substr($ciphertext, 16);

        $plain = openssl_decrypt($body, 'aes-128-cbc', $key, \OPENSSL_RAW_DATA, $iv);
        if (false === $plain) {
            throw new EncryptionException('AES-128-CBC decrypt failed: '.openssl_error_string());
        }

        return $plain;
    }

    /**
     * Pad/truncate the password per Algorithm 2 step (a): the first
     * 32 bytes of (password ‖ padding-constant).
     */
    private static function padPassword(string $password): string
    {
        return substr($password.self::PADDING, 0, 32);
    }

    /**
     * Resolve whether streams and strings use AES-128 by walking the
     * /CF crypt-filter table for R=4. R=2 and R=3 are always RC4.
     */
    private static function resolveUseAes(array $encryptDict): bool
    {
        $v = (int) ($encryptDict['V'] ?? 0);
        if ($v < 4) {
            return false;
        }

        // For V=4, /StmF and /StrF name an entry in /CF whose /CFM
        // entry is /V2 (RC4) or /AESV2 (AES-128).
        $stmF = $encryptDict['StmF'] ?? 'Identity';
        $strF = $encryptDict['StrF'] ?? 'Identity';
        if ($stmF !== $strF) {
            throw new UnsupportedSecurityHandlerException(
                'Split crypt filters (StmF != StrF) are not supported.'
            );
        }
        if ('Identity' === $stmF) {
            // Identity = no encryption for this stream class. We bail
            // because content streams unencrypted but the file key still
            // exists is a degenerate, uncommon configuration.
            throw new UnsupportedSecurityHandlerException(
                'Identity crypt filter for streams is not supported.'
            );
        }

        $cf = $encryptDict['CF'] ?? [];
        $filter = $cf[$stmF] ?? null;
        if (!\is_array($filter)) {
            throw new UnsupportedSecurityHandlerException(
                'Crypt filter "'.$stmF.'" not found in /CF.'
            );
        }
        $cfm = $filter['CFM'] ?? 'V2';
        if ('V2' === $cfm) {
            return false;
        }
        if ('AESV2' === $cfm) {
            return true;
        }
        throw new UnsupportedSecurityHandlerException(
            'Unsupported crypt filter method /CFM /'.$cfm
        );
    }

    /**
     * Effective file-encryption-key length in bytes for the configured
     * revision. R=2 is hardcoded to 5 bytes (40 bits); later revisions
     * read /Length (bits) from the dictionary, defaulting to 40 if
     * absent. R=4 with AES is always 16 bytes regardless of /Length.
     */
    private function keyLengthBytes(array $encryptDict): int
    {
        if (2 === $this->revision) {
            return 5;
        }
        if (4 === $this->revision && $this->useAes) {
            return 16;
        }
        $bits = (int) ($encryptDict['Length'] ?? 40);
        if ($bits < 40 || $bits > 128 || 0 !== $bits % 8) {
            throw new EncryptionException('Invalid /Length: '.$bits);
        }

        return intdiv($bits, 8);
    }

    /**
     * XOR every byte of $bytes with the single byte $b. Used by
     * Algorithm 5 to derive the per-iteration RC4 key.
     */
    private static function xorByteWise(string $bytes, string $b): string
    {
        $mask = str_repeat($b, \strlen($bytes));

        return $bytes ^ $mask;
    }

    /**
     * @return array{0:int,1:int}
     */
    private static function splitObjRef(string $objRef): array
    {
        $parts = explode('_', $objRef);
        if (2 !== \count($parts)) {
            throw new EncryptionException('Malformed objref: '.$objRef);
        }

        return [(int) $parts[0], (int) $parts[1]];
    }
}
