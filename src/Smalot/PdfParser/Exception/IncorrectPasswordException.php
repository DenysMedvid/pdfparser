<?php

declare(strict_types=1);

namespace Smalot\PdfParser\Exception;

/**
 * Thrown when the supplied decryption password fails to unlock an
 * encrypted PDF.
 */
class IncorrectPasswordException extends EncryptionException
{
}
