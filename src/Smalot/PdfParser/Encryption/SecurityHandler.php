<?php

declare(strict_types=1);

namespace Smalot\PdfParser\Encryption;

use Smalot\PdfParser\Exception\EncryptionException;
use Smalot\PdfParser\Exception\NotImplementedException;
use Smalot\PdfParser\Exception\UnsupportedSecurityHandlerException;

/**
 * Public-facing facade for PDF decryption used by RawDataParser.
 *
 * Construction: a RawDataParser instance has already located the trailer
 * and the /Encrypt indirect object; it asks
 * {@see SecurityHandler::fromRawEncryptObject()} to build a handler
 * keyed on the requested password.
 *
 * Lifetime: one SecurityHandler per parsed document.
 */
final class SecurityHandler
{
    /** @var StandardSecurityHandler */
    private $strategy;

    /** @var string objref ("N_G") of the /Encrypt object itself. */
    private $encryptObjRef;

    /** @var bool */
    private $encryptMetadata;

    /** @var bool */
    private $inObjectStream = false;

    private function __construct(
        StandardSecurityHandler $strategy,
        string $encryptObjRef,
        bool $encryptMetadata
    ) {
        $this->strategy = $strategy;
        $this->encryptObjRef = $encryptObjRef;
        $this->encryptMetadata = $encryptMetadata;
    }

    /**
     * Build a SecurityHandler from a *raw* /Encrypt object as produced by
     * {@see \Smalot\PdfParser\RawData\RawDataParser::getIndirectObject()}.
     *
     * @param array  $rawEncryptObj Raw object content array.
     * @param string $encryptObjRef "N_G" form of the /Encrypt object reference.
     * @param string $fileId        Raw bytes of /ID[0] from the trailer.
     * @param string $password      Decryption password (empty supported).
     */
    public static function fromRawEncryptObject(
        array $rawEncryptObj,
        string $encryptObjRef,
        string $fileId,
        string $password
    ): self {
        // Non-empty passwords are out of scope for the first iteration.
        // The setter exists on Config purely for API stability; refuse
        // here so callers get a clear signal rather than silent failure.
        if ('' !== $password) {
            throw new NotImplementedException(
                'Only the empty user password is currently supported by '
                .'SecurityHandler. Non-empty passwords are not yet implemented.'
            );
        }

        $encryptDict = self::normalizeEncryptDict($rawEncryptObj);

        $filter = $encryptDict['Filter'] ?? null;
        if ('Standard' !== $filter) {
            throw new UnsupportedSecurityHandlerException(
                'Only the Standard security handler is supported (got /Filter /'
                .(\is_string($filter) ? $filter : 'unknown').').'
            );
        }

        $revision = (int) ($encryptDict['R'] ?? 0);
        $encryptMetadata = (bool) ($encryptDict['EncryptMetadata'] ?? true);

        switch ($revision) {
            case 2:
            case 3:
            case 4:
                $strategy = new StandardSecurityHandlerR4($encryptDict, $fileId, $password);
                break;
            case 5:
                $strategy = new StandardSecurityHandlerR5($encryptDict, $fileId, $password);
                break;
            case 6:
                $strategy = new StandardSecurityHandlerR6($encryptDict, $fileId, $password);
                break;
            default:
                throw new UnsupportedSecurityHandlerException(
                    'Unsupported Standard handler revision R='.$revision
                );
        }

        return new self($strategy, $encryptObjRef, $encryptMetadata);
    }

    public function decryptString(string $ciphertext, string $objRef): string
    {
        return $this->strategy->decryptBytes($ciphertext, $objRef);
    }

    public function decryptStream(string $ciphertext, string $objRef): string
    {
        return $this->strategy->decryptBytes($ciphertext, $objRef);
    }

    /**
     * The /Encrypt object itself is *never* decrypted; nor are objects
     * unpacked from inside an /ObjStm (those are decrypted once at the
     * outer ObjStm stream level).
     */
    public function isExempt(string $objRef): bool
    {
        if ($this->inObjectStream) {
            return true;
        }

        return $objRef === $this->encryptObjRef;
    }

    public function shouldDecryptMetadata(): bool
    {
        return $this->encryptMetadata;
    }

    public function setInObjectStream(bool $flag): void
    {
        $this->inObjectStream = $flag;
    }

    /**
     * Walk a raw indirect-object structure and produce a normalized
     * PHP array of the /Encrypt dictionary.
     *
     * Input shape (from RawDataParser): a list of `[type, value, offset]`
     * triples. Exactly one of them is the outer dict header
     * `['<<', [...key/value pairs...], offset]`.
     *
     * @return array<string,mixed>
     */
    private static function normalizeEncryptDict(array $rawObj): array
    {
        foreach ($rawObj as $element) {
            if (\is_array($element) && '<<' === ($element[0] ?? null)) {
                return self::flattenDict($element[1]);
            }
        }
        throw new EncryptionException('Could not find /Encrypt dictionary body.');
    }

    /**
     * @param array<int,array> $entries Alternating key/value entries from a raw dict.
     *
     * @return array<string,mixed>
     */
    private static function flattenDict(array $entries): array
    {
        $result = [];
        $count = \count($entries);
        for ($i = 0; $i + 1 < $count; $i += 2) {
            $key = $entries[$i];
            $val = $entries[$i + 1];
            if (!\is_array($key) || '/' !== ($key[0] ?? null) || !\is_string($key[1] ?? null)) {
                continue;
            }
            $result[$key[1]] = self::decodeRawValue($val);
        }

        return $result;
    }

    /**
     * Convert a single raw `[type, value, offset]` entry into a PHP
     * primitive: int / float / bool / string / array.
     *
     */
    private static function decodeRawValue(array $element)
    {
        $type = $element[0] ?? null;
        $value = $element[1] ?? null;

        switch ($type) {
            case 'numeric':
                if (\is_string($value) && false !== strpos($value, '.')) {
                    return (float) $value;
                }

                return (int) $value;

            case 'boolean':
                return 'true' === $value;

            case 'null':
                return null;

            case '/':
                // Name object — value is already a UTF-8 string.
                return (string) $value;

            case '(':
                // Literal string — PDF-unescape to raw bytes.
                return self::pdfUnescapeLiteral((string) $value);

            case '<':
                // Hex string — strip whitespace, then hex2bin.
                $hex = (string) $value;
                if (1 === (\strlen($hex) & 1)) {
                    // Odd length: trailing nibble is 0 per spec.
                    $hex .= '0';
                }

                return (string) hex2bin($hex);

            case '<<':
                return self::flattenDict((array) $value);

            case '[':
                $out = [];
                foreach ((array) $value as $sub) {
                    if (\is_array($sub)) {
                        $out[] = self::decodeRawValue($sub);
                    }
                }

                return $out;

            case 'objref':
                // Indirect references are not resolvable here; preserve
                // as an opaque marker. We don't expect /Encrypt to use
                // indirect values for the entries we read, but keep
                // round-trip safe.
                return ['__objref' => (string) $value];

            default:
                return $value;
        }
    }

    /**
     * Reverse the PDF literal-string escape syntax (spec §7.3.4.2)
     * to recover the raw bytes of an /O, /U, /OE, /UE, etc. value.
     *
     * Recognised escapes: \n \r \t \b \f \( \) \\ \<octal{1,3}>
     * Line continuation (\ followed by EOL) is also collapsed.
     */
    public static function pdfUnescapeLiteral(string $raw): string
    {
        $out = '';
        $len = \strlen($raw);
        for ($i = 0; $i < $len; ++$i) {
            $ch = $raw[$i];
            if ('\\' !== $ch) {
                $out .= $ch;
                continue;
            }
            // Backslash with nothing after — drop it.
            if ($i + 1 >= $len) {
                break;
            }
            $next = $raw[$i + 1];
            switch ($next) {
                case 'n': $out .= "\n";
                    ++$i;
                    break;
                case 'r': $out .= "\r";
                    ++$i;
                    break;
                case 't': $out .= "\t";
                    ++$i;
                    break;
                case 'b': $out .= "\x08";
                    ++$i;
                    break;
                case 'f': $out .= "\f";
                    ++$i;
                    break;
                case '(': $out .= '(';
                    ++$i;
                    break;
                case ')': $out .= ')';
                    ++$i;
                    break;
                case '\\': $out .= '\\';
                    ++$i;
                    break;
                case "\r":
                    // Line continuation: skip CR and optional LF.
                    ++$i;
                    if ($i + 1 < $len && "\n" === $raw[$i + 1]) {
                        ++$i;
                    }
                    break;
                case "\n":
                    ++$i; // line continuation
                    break;
                default:
                    if ($next >= '0' && $next <= '7') {
                        // Octal escape: up to three digits.
                        $oct = $next;
                        ++$i;
                        for ($k = 0; $k < 2; ++$k) {
                            if ($i + 1 < $len && $raw[$i + 1] >= '0' && $raw[$i + 1] <= '7') {
                                $oct .= $raw[$i + 1];
                                ++$i;
                            } else {
                                break;
                            }
                        }
                        $out .= \chr(octdec($oct) & 0xFF);
                    } else {
                        // Unknown escape — per spec, backslash is dropped.
                        $out .= $next;
                        ++$i;
                    }
            }
        }

        return $out;
    }
}
