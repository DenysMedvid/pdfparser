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
use Smalot\PdfParser\Encryption\RC4;

class RC4Test extends TestCase
{
    /**
     * Known-answer test from RFC 6229 §2 — key 0x0102030405,
     * 16-byte all-zero plaintext.
     */
    public function testRfc6229SmallKey(): void
    {
        $key = hex2bin('0102030405');
        $plaintext = str_repeat("\x00", 16);

        $this->assertSame(
            'b2396305f03dc027ccc3524a0a1118a8',
            bin2hex(RC4::process($key, $plaintext))
        );
    }

    /**
     * RC4 is symmetric — encrypting twice returns the original.
     */
    public function testEncryptDecryptRoundTrip(): void
    {
        $key = 'PDFKey';
        $message = 'The quick brown fox jumps over the lazy dog.';

        $cipher = RC4::process($key, $message);
        $this->assertNotSame($message, $cipher);

        $plain = RC4::process($key, $cipher);
        $this->assertSame($message, $plain);
    }

    public function testEmptyKeyIsNoOp(): void
    {
        $this->assertSame('hello', RC4::process('', 'hello'));
    }
}
