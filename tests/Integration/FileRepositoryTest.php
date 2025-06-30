<?php

namespace WebauthnEmulator\Tests\Integration;

use WebauthnEmulator\CredentialRepository\FileRepository;
use WebauthnEmulator\CredentialRepository\RepositoryInterface;

class FileRepositoryTest extends AbstractRepositoryTest
{
    private string $storagePath;

    protected function setUp(): void
    {
        // tempnam creates a unique file with 0600 permissions, which is good for tests.
        $path = tempnam(sys_get_temp_dir(), 'webauthn_test_');
        if ($path === false) {
            $this->fail('Could not create temporary file for test.');
        }
        $this->storagePath = $path;
    }

    protected function tearDown(): void
    {
        if (file_exists($this->storagePath)) {
            unlink($this->storagePath);
        }
    }

    protected function createRepository(): RepositoryInterface
    {
        return new FileRepository($this->storagePath);
    }

    public function testConstructorCreatesFile()
    {
        $path = sys_get_temp_dir() . '/webauthn_test_file_' . uniqid() . '.txt';
        $this->assertFileDoesNotExist($path);
        new FileRepository($path);
        $this->assertFileExists($path);
        unlink($path);
    }

    public function testConstructorCreatesDirectoryAndFile()
    {
        $dir = sys_get_temp_dir() . '/webauthn_test_dir_' . uniqid();
        $path = $dir . '/storage.txt';
        $this->assertDirectoryDoesNotExist($dir);

        new FileRepository($path);

        $this->assertDirectoryExists($dir);
        $this->assertFileExists($path);

        // cleanup
        unlink($path);
        rmdir($dir);
    }

}
