<?php

namespace WebauthnEmulator\CredentialRepository;

use RuntimeException;
use WebauthnEmulator\CredentialInterface;

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
     * @throws RuntimeException
     */
    public function getById(string $rpId, string $id): CredentialInterface;
}