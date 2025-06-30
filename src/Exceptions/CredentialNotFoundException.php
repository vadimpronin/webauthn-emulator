<?php

declare(strict_types=1);

namespace WebauthnEmulator\Exceptions;

class CredentialNotFoundException extends WebauthnEmulatorException
{
    protected $code = 404;
    protected $message = 'Credential not found';
}
