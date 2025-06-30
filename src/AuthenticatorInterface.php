<?php

declare(strict_types=1);

namespace WebauthnEmulator;

use WebauthnEmulator\CredentialRepository\RepositoryInterface;

interface AuthenticatorInterface
{
    public function __construct(RepositoryInterface $repository);
    public function getAttestation(array $registerOptions): array;
    public function getAssertion(string $rpId, string|array|null $credentialIds, string $challenge): array;

    public static function base64Normal2Url(string|array $base64Encoded): string|array;
    public static function base64Url2Normal(string|array $base64urlEncoded): string|array;
}
