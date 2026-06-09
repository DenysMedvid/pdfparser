<?php

/**
 * @file This file is part of the PdfParser library.
 *
 * @license LGPLv3
 *
 * @url     <https://github.com/smalot/pdfparser>
 */

declare(strict_types=1);

namespace PHPUnitTests\Unit\Encryption;

use PHPUnitTests\TestCase;
use Smalot\PdfParser\Encryption\StandardSecurityHandlerR5;
use Smalot\PdfParser\Exception\EncryptionException;
use Smalot\PdfParser\Exception\IncorrectPasswordException;

class StandardSecurityHandlerR5Test extends TestCase
{
    /**
     * Reproduces the unlock of samples/encrypted/r5_aes_256.pdf with
     * an empty user password — the authentication hash and AES-CBC
     * file-key decrypt are the entire R=5 algorithm in one assertion.
     */
    public function testEmptyPasswordUnlocksFixture(): void
    {
        $handler = new StandardSecurityHandlerR5($this->fixtureDict(), '', '');
        $this->assertNotNull($handler);
    }

    public function testWrongPasswordThrows(): void
    {
        $this->expectException(IncorrectPasswordException::class);

        new StandardSecurityHandlerR5($this->fixtureDict(), '', 'wrong-password');
    }

    public function testShortUEntryIsRejected(): void
    {
        $dict = $this->fixtureDict();
        $dict['U'] = substr($dict['U'], 0, 32);

        $this->expectException(EncryptionException::class);
        new StandardSecurityHandlerR5($dict, '', '');
    }

    /**
     * AES-256-CBC round trip: encrypt a known plaintext with the file
     * key we just derived, then decrypt via the handler.
     */
    public function testDecryptsAes256RoundTrip(): void
    {
        $handler = new StandardSecurityHandlerR5($this->fixtureDict(), '', '');

        // Pull the file key out via reflection (it's private — the
        // public API never exposes raw keys).
        $rp = new \ReflectionProperty(StandardSecurityHandlerR5::class, 'fileKey');
        $rp->setAccessible(true);
        $fileKey = $rp->getValue($handler);
        $this->assertSame(32, \strlen($fileKey));

        $plain = 'A short test plaintext.';
        $iv = random_bytes(16);
        $cipher = openssl_encrypt($plain, 'aes-256-cbc', $fileKey, \OPENSSL_RAW_DATA, $iv);

        // R=5/6 have no per-object key derivation, so objRef is unused.
        $this->assertSame($plain, $handler->decryptBytes($iv.$cipher, '4_0'));
    }

    /**
     * /Encrypt dict for samples/encrypted/r5_aes_256.pdf.
     *
     * @return array<string,mixed>
     */
    private function fixtureDict(): array
    {
        return [
            'Filter' => 'Standard',
            'V' => 5,
            'R' => 5,
            'Length' => 256,
            'U' => hex2bin('832e5574b234ef2ef03f4b804799723214322dfa75154fac871b05c4f4338a885cd2608e1feab3d1858adfa36de43259'),
            'UE' => hex2bin('5741cdc45df671462250e2f4db44b7cd2e1862b6fe6aff73f0df8c3ea0a12f4f'),
        ];
    }
}
