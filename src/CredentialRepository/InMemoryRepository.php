<?php

declare(strict_types = 1);

namespace WebauthnEmulator\CredentialRepository;

use WebauthnEmulator\CredentialInterface;
use WebauthnEmulator\Exceptions\CredentialNotFoundException;

class InMemoryRepository implements RepositoryInterface
{
    private array $credentials = [];

    public function save(CredentialInterface $credential): static
    {
        $this->credentials[$credential->getRpId()][$credential->getId()] = $credential;

        return $this;
    }

    public function get(string $rpId): array
    {
        return $this->credentials[$rpId] ?? [];
    }

    public function getById(string $rpId, string $id): CredentialInterface
    {
        $credential = $this->credentials[$rpId][$id] ?? null;
        if ($credential === null) {
            throw new CredentialNotFoundException('credential not found');
        }

        return $credential;
    }
}