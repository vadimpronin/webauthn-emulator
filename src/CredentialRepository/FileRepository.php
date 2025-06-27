<?php

declare(strict_types=1);

namespace WebauthnEmulator\CredentialRepository;

use RuntimeException;
use WebauthnEmulator\CredentialInterface;
use WebauthnEmulator\Exceptions\CredentialNotFoundException;

/**
 * Test example. Do not use in PROD!
 */
class FileRepository implements RepositoryInterface
{
    protected array $credentials = [];

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
        if (!empty($storageContent)) {
            $this->credentials = unserialize($storageContent, ["allowed_classes" => true]);
        }
    }

    public function save(CredentialInterface $credential): static
    {
        $this->credentials[$credential->getRpId()][$credential->getId()] = $credential;
        file_put_contents($this->storagePath, serialize($this->credentials));

        return $this;
    }

    /**
     * @param string $rpId
     *
     * @return CredentialInterface[]
     */
    public function get(string $rpId): array
    {
        return $this->credentials[$rpId] ?? [];
    }

    /**
     * @throws CredentialNotFoundException
     */
    public function getById(string $rpId, string $id): CredentialInterface
    {
        $credential = $this->credentials[$rpId][$id] ?? null;
        if ($credential === null) {
            throw new CredentialNotFoundException('credential not found');
        }

        return $credential;
    }
}
