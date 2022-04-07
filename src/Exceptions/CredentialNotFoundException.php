<?php

namespace WebauthnEmulator\Exceptions;

class CredentialNotFoundException extends WebauthnEmulatorException
{
    protected $code = 404;
    protected $message = 'Credential not found';
}