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
use Smalot\PdfParser\Encryption\StandardSecurityHandlerR4;
use Smalot\PdfParser\Exception\IncorrectPasswordException;
use Smalot\PdfParser\Exception\UnsupportedSecurityHandlerException;

/**
 * Known-answer tests for StandardSecurityHandlerR4 covering all three
 * revisions it handles. KATs are derived from the qpdf-generated
 * fixtures under samples/encrypted/ — see those fixtures' /Encrypt
 * dictionaries for ground truth.
 */
class StandardSecurityHandlerR4Test extends TestCase
{
    /** Shared trailer /ID[0] across all R=2..R=4 fixtures. */
    private const FILE_ID_HEX = '984da96b7c5e60408bb1afe2fe6b6c03';

    public function testR2AcceptsEmptyPassword(): void
    {
        $handler = new StandardSecurityHandlerR4(
            $this->r2Dict(),
            hex2bin(self::FILE_ID_HEX),
            ''
        );
        $this->assertNotNull($handler);
    }

    public function testR3AcceptsEmptyPassword(): void
    {
        $handler = new StandardSecurityHandlerR4(
            $this->r3Dict(),
            hex2bin(self::FILE_ID_HEX),
            ''
        );
        $this->assertNotNull($handler);
    }

    public function testR4Rc4AcceptsEmptyPassword(): void
    {
        $handler = new StandardSecurityHandlerR4(
            $this->r4Dict('V2'),
            hex2bin(self::FILE_ID_HEX),
            ''
        );
        $this->assertNotNull($handler);
    }

    public function testR4AesAcceptsEmptyPassword(): void
    {
        $handler = new StandardSecurityHandlerR4(
            $this->r4Dict('AESV2'),
            hex2bin(self::FILE_ID_HEX),
            ''
        );
        $this->assertNotNull($handler);
    }

    public function testR3RejectsWrongPassword(): void
    {
        $this->expectException(IncorrectPasswordException::class);

        new StandardSecurityHandlerR4(
            $this->r3Dict(),
            hex2bin(self::FILE_ID_HEX),
            'this-is-the-wrong-password'
        );
    }

    public function testRevisionOutsideRangeIsRejected(): void
    {
        $this->expectException(UnsupportedSecurityHandlerException::class);

        new StandardSecurityHandlerR4(
            ['R' => 5] + $this->r3Dict(),
            hex2bin(self::FILE_ID_HEX),
            ''
        );
    }

    public function testSplitStmfStrfFiltersAreRejected(): void
    {
        $dict = $this->r4Dict('AESV2');
        $dict['StrF'] = 'OtherCF';
        $dict['CF']['OtherCF'] = ['CFM' => 'V2', 'Length' => 16];

        $this->expectException(UnsupportedSecurityHandlerException::class);
        new StandardSecurityHandlerR4($dict, hex2bin(self::FILE_ID_HEX), '');
    }

    /**
     * Round-trip: a successfully-authenticated R=3 handler should be
     * able to decrypt RC4 ciphertext we encrypt manually with the same
     * per-object key derivation.
     */
    public function testR3DecryptsStringRoundTrip(): void
    {
        $handler = new StandardSecurityHandlerR4(
            $this->r3Dict(),
            hex2bin(self::FILE_ID_HEX),
            ''
        );
        // Manually encrypt the same plaintext with the per-object key
        // derivation defined by Algorithm 1 (mirrored in this class
        // for the test only) and confirm decrypting gives plaintext.
        $plain = 'Hello, encrypted PDF world.';
        $objRef = '4_0';

        $fileKey = $this->reproduceR3FileKey();
        $perObjKey = $this->reproduceR3ObjectKey($fileKey, 4, 0);

        $cipher = \Smalot\PdfParser\Encryption\RC4::process($perObjKey, $plain);

        $this->assertSame($plain, $handler->decryptBytes($cipher, $objRef));
    }

    /**
     * Encrypt dictionary used by samples/encrypted/r2_rc4_40.pdf.
     *
     * @return array<string,mixed>
     */
    private function r2Dict(): array
    {
        return [
            'Filter' => 'Standard',
            'V' => 1,
            'R' => 2,
            'Length' => 40,
            'O' => hex2bin('2055c756c72e1ad702608e8196acad447ad32d17cff583235f6dd15fed7dab67'),
            'U' => hex2bin('d184b31bde0a2ae19bef7c505ef3c16026b138e4d4b916aa7c651bb476c9332f'),
            'P' => -4,
        ];
    }

    /**
     * @return array<string,mixed>
     */
    private function r3Dict(): array
    {
        return [
            'Filter' => 'Standard',
            'V' => 2,
            'R' => 3,
            'Length' => 128,
            'O' => hex2bin('36451bd39d753b7c1d10922c28e6665aa4f3353fb0348b536893e3b1db5c579b'),
            'U' => hex2bin('78465f8251359426765aa8c5d6cc13a40021446990b9e4114071a4d9104984c1'),
            'P' => -4,
        ];
    }

    /**
     * @return array<string,mixed>
     */
    private function r4Dict(string $cfm): array
    {
        return [
            'Filter' => 'Standard',
            'V' => 4,
            'R' => 4,
            'Length' => 128,
            'O' => hex2bin('36451bd39d753b7c1d10922c28e6665aa4f3353fb0348b536893e3b1db5c579b'),
            'U' => hex2bin('78465f8251359426765aa8c5d6cc13a40021446990b9e4114071a4d9104984c1'),
            'P' => -4,
            'StmF' => 'StdCF',
            'StrF' => 'StdCF',
            'CF' => ['StdCF' => ['CFM' => $cfm, 'Length' => 16]],
        ];
    }

    private function reproduceR3FileKey(): string
    {
        $padding = "\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A";
        $dict = $this->r3Dict();
        $material = $padding.$dict['O'].pack('V', $dict['P'] & 0xFFFFFFFF).hex2bin(self::FILE_ID_HEX);
        $hash = md5($material, true);
        for ($i = 0; $i < 50; ++$i) {
            $hash = md5(substr($hash, 0, 16), true);
        }

        return substr($hash, 0, 16);
    }

    private function reproduceR3ObjectKey(string $fileKey, int $objNum, int $genNum): string
    {
        $material = $fileKey
            .substr(pack('V', $objNum), 0, 3)
            .substr(pack('V', $genNum), 0, 2);
        $hash = md5($material, true);

        return substr($hash, 0, min(\strlen($fileKey) + 5, 16));
    }
}
