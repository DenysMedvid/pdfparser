<?php

declare(strict_types=1);

namespace Smalot\PdfParser\Exception;

/**
 * Base exception for errors raised by the encryption / security-handler
 * subsystem. Concrete failure modes (wrong password, unsupported handler,
 * etc.) extend this class.
 */
class EncryptionException extends \Exception
{
}
