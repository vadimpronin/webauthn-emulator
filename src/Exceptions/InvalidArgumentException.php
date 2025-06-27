<?php

declare(strict_types=1);

namespace WebauthnEmulator\Exceptions;

class InvalidArgumentException extends WebauthnEmulatorException
{
    protected $code = 422;
    protected $message = 'Invalid argument';
}
