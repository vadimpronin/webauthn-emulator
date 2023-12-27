<?php

namespace WebauthnEmulator;

use WebauthnEmulator\CredentialRepository\RepositoryInterface;

interface AuthenticatorInterface
{
    public function __construct(RepositoryInterface $repository);
    public function getAttestation(array $registerOptions): array;
    public function getAssertion(string $rpId, string|array|null $credentialIds, string $challenge): array;
}
