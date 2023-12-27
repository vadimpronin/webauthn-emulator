<?php

namespace WebauthnEmulator\CredentialRepository;

use WebauthnEmulator\CredentialInterface;
use WebauthnEmulator\Exceptions\CredentialNotFoundException;

interface RepositoryInterface
{
    public function save(CredentialInterface $credential): static;

    /**
     * @param string $rpId - relay part identifier (return on init)
     *
     * @return CredentialInterface[]
     */
    public function get(string $rpId): array;

    /**
     * @throws CredentialNotFoundException
     */
    public function getById(string $rpId, string $id): CredentialInterface;
}
