<?php

namespace WebauthnEmulator\Exceptions;

class InvalidArgumentException extends WebauthnEmulatorException
{
    protected $code = 422;
    protected $message = 'Invalid argument';
}
