<?php

namespace WebauthnEmulator\Tests\Integration;

use WebauthnEmulator\CredentialRepository\InMemoryRepository;
use WebauthnEmulator\CredentialRepository\RepositoryInterface;

class InMemoryRepositoryTest extends AbstractRepositoryTest
{
    protected static InMemoryRepository $repository;

    protected function createRepository(): RepositoryInterface
    {
        if (!isset(self::$repository)) {
            self::$repository = new InMemoryRepository();
        }

        return self::$repository;
    }
}
