<?php

namespace WebauthnEmulator\CredentialRepository;

use JsonException;
use RuntimeException;
use WebauthnEmulator\CredentialFactory;
use WebauthnEmulator\CredentialInterface;
use WebauthnEmulator\Exceptions\CredentialNotFoundException;

/**
 * Test example. Do not use in PROD!
 */
class FileRepository implements RepositoryInterface
{
    private array $currentState;

    /**
     * @throws JsonException
     */
    public function __construct(
        private string $storagePath
    )
    {
        $storageDir = dirname($this->storagePath);
        if (!file_exists($storageDir) && !mkdir(directory: $storageDir, recursive: true) && !is_dir($storageDir)) {
            throw new RuntimeException(sprintf('Directory "%s" was not created', $storageDir));
        }
        if (!file_exists($this->storagePath)) {
            touch(filename: $this->storagePath);
        }

        $storageContent = file_get_contents($this->storagePath);
        $this->currentState = $storageContent === '' ? [] : json_decode($storageContent, true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * @throws JsonException
     */
    public function __destruct()
    {
        file_put_contents($this->storagePath, json_encode($this->currentState, JSON_THROW_ON_ERROR));
    }

    public function save(CredentialInterface $credential): static
    {
        $this->currentState[$credential->getRpId()][$credential->getId()] = $credential->toArray();
        return $this;
    }

    /**
     * @param string $rpId
     *
     * @return CredentialInterface[]
     */
    public function get(string $rpId): array
    {
        return $this->currentState[$rpId] ?? [];
    }

    /**
     * @throws CredentialNotFoundException
     */
    public function getById(string $rpId, string $id): CredentialInterface
    {
        $credentialData = $this->currentState[$rpId][$id] ?? null;
        if (null === $credentialData) {
            throw new CredentialNotFoundException('credential not found');
        }

        $credential = CredentialFactory::makeFromArray($credentialData);

        $credential->incrementSignCount();
        return $credential;
    }
}
