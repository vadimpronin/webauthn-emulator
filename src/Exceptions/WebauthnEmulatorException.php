<?php

declare(strict_types=1);

namespace WebauthnEmulator\Exceptions;

use RuntimeException;

class WebauthnEmulatorException extends RuntimeException
{
    protected $code = 500;
    protected $message = 'Webauthn emulator unknown error';
}
