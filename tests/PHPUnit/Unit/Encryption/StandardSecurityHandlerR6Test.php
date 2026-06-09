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
use Smalot\PdfParser\Encryption\StandardSecurityHandlerR6;
use Smalot\PdfParser\Exception\IncorrectPasswordException;

/**
 * R=6 tests focus on Algorithm 2.B — the iterated SHA-256/384/512 +
 * AES-128-CBC key derivation that is unique to PDF 2.0. Constructing
 * the handler successfully against a real fixture's /U+/UE is the
 * tightest end-to-end assertion for that algorithm.
 */
class StandardSecurityHandlerR6Test extends TestCase
{
    public function testEmptyPasswordUnlocksFixture(): void
    {
        $handler = new StandardSecurityHandlerR6($this->fixtureDict(), '', '');
        $this->assertNotNull($handler);
    }

    public function testWrongPasswordThrows(): void
    {
        $this->expectException(IncorrectPasswordException::class);

        new StandardSecurityHandlerR6($this->fixtureDict(), '', 'wrong');
    }

    public function testDecryptsAes256RoundTrip(): void
    {
        $handler = new StandardSecurityHandlerR6($this->fixtureDict(), '', '');

        $rp = new \ReflectionProperty(StandardSecurityHandlerR6::class, 'fileKey');
        $rp->setAccessible(true);
        $fileKey = $rp->getValue($handler);
        $this->assertSame(32, \strlen($fileKey));

        $plain = 'PDF 2.0 round trip plaintext.';
        $iv = random_bytes(16);
        $cipher = openssl_encrypt($plain, 'aes-256-cbc', $fileKey, \OPENSSL_RAW_DATA, $iv);

        $this->assertSame($plain, $handler->decryptBytes($iv.$cipher, '4_0'));
    }

    /**
     * /Encrypt dict for samples/encrypted/r6_aes_256.pdf.
     *
     * @return array<string,mixed>
     */
    private function fixtureDict(): array
    {
        return [
            'Filter' => 'Standard',
            'V' => 5,
            'R' => 6,
            'Length' => 256,
            'U' => hex2bin('31bca08be7c121ae07d8757b3c9a422844368e4a09ffd5951789454a95145ca627cc143dca1e552c6a78d0ca195b1d63'),
            'UE' => hex2bin('190bde866bd328b7401701aaad401965c8335f38c783f067178b40f5f0f37bf2'),
        ];
    }
}
