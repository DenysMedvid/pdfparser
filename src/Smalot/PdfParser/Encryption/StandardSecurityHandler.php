<?php

declare(strict_types=1);

namespace Smalot\PdfParser\Encryption;

/**
 * Interface for per-revision implementations of the PDF Standard
 * Security Handler (ISO 32000-1 §7.6.3, ISO 32000-2 §7.6.4).
 *
 * Each revision differs in key derivation and the cipher used; the
 * dispatching {@see SecurityHandler} selects the right implementation
 * based on the /R entry of the /Encrypt dictionary.
 */
interface StandardSecurityHandler
{
    /**
     * Decrypt one indirect object's worth of ciphertext bytes.
     *
     * The same routine handles both literal/hex strings and stream
     * bodies. For AES revisions the input is expected to start with
     * the 16-byte IV produced by the encrypting writer.
     *
     * @param string $ciphertext Raw encrypted bytes (post-PDF-decoding).
     * @param string $objRef     "<objNum>_<genNum>" of the *containing*
     *                           indirect object. Used to derive the
     *                           per-object key in revisions ≤ 4.
     */
    public function decryptBytes(string $ciphertext, string $objRef): string;
}
