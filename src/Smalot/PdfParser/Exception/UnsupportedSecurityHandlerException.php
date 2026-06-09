<?php

declare(strict_types=1);

namespace Smalot\PdfParser\Exception;

/**
 * Thrown when an encrypted PDF uses a security handler or revision the
 * library cannot process (e.g. public-key handler, unknown crypt filter,
 * or a Standard handler revision outside the supported range).
 */
class UnsupportedSecurityHandlerException extends EncryptionException
{
}
