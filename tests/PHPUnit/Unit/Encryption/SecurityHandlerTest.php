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
use Smalot\PdfParser\Encryption\SecurityHandler;
use Smalot\PdfParser\Exception\NotImplementedException;
use Smalot\PdfParser\Exception\UnsupportedSecurityHandlerException;

class SecurityHandlerTest extends TestCase
{
    public function testNonEmptyPasswordThrowsNotImplemented(): void
    {
        $this->expectException(NotImplementedException::class);

        SecurityHandler::fromRawEncryptObject(
            $this->minimalRawEncryptObj(),
            '23_0',
            '',
            'not-empty'
        );
    }

    public function testUnsupportedFilterIsRejected(): void
    {
        $raw = $this->minimalRawEncryptObj('Adobe.PubSec');

        $this->expectException(UnsupportedSecurityHandlerException::class);
        SecurityHandler::fromRawEncryptObject($raw, '23_0', '', '');
    }

    public function testUnknownRevisionIsRejected(): void
    {
        $raw = $this->minimalRawEncryptObj('Standard', 99);

        $this->expectException(UnsupportedSecurityHandlerException::class);
        SecurityHandler::fromRawEncryptObject($raw, '23_0', '', '');
    }

    /**
     * The pdfUnescapeLiteral helper must invert every escape sequence
     * recognised by PDF spec §7.3.4.2 — backslash escapes, octal
     * escapes, and line-continuation.
     */
    public function testPdfUnescapeLiteralCoversAllEscapes(): void
    {
        $this->assertSame("\n\r\t\x08\x0c", SecurityHandler::pdfUnescapeLiteral('\\n\\r\\t\\b\\f'));
        $this->assertSame('()\\', SecurityHandler::pdfUnescapeLiteral('\\(\\)\\\\'));
        $this->assertSame("A\x07B", SecurityHandler::pdfUnescapeLiteral('A\\7B'));
        $this->assertSame("\xFF", SecurityHandler::pdfUnescapeLiteral('\\377'));
        $this->assertSame('plain', SecurityHandler::pdfUnescapeLiteral('plain'));
        $this->assertSame('AB', SecurityHandler::pdfUnescapeLiteral("A\\\nB"));
        $this->assertSame('AB', SecurityHandler::pdfUnescapeLiteral("A\\\r\nB"));
    }

    /**
     * Build a raw indirect-object structure that mimics what
     * RawDataParser::getIndirectObject() would return for a stub
     * /Encrypt dict — just enough to drive the dispatcher's branches.
     *
     * @return array<int,array>
     */
    private function minimalRawEncryptObj(string $filter = 'Standard', int $revision = 3): array
    {
        return [
            [
                '<<',
                [
                    ['/', 'Filter', 0], ['/', $filter, 0],
                    ['/', 'V', 0], ['numeric', '2', 0],
                    ['/', 'R', 0], ['numeric', (string) $revision, 0],
                    ['/', 'Length', 0], ['numeric', '128', 0],
                    ['/', 'O', 0], ['<', str_repeat('00', 32), 0],
                    ['/', 'U', 0], ['<', str_repeat('00', 32), 0],
                    ['/', 'P', 0], ['numeric', '-4', 0],
                ],
                0,
            ],
        ];
    }
}
