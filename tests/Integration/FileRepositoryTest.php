<?php

namespace WebauthnEmulator\Tests\Integration;

use PHPUnit\Framework\TestCase;
use WebauthnEmulator\Credential;
use WebauthnEmulator\CredentialRepository\FileRepository;
use WebauthnEmulator\Exceptions\CredentialNotFoundException;

class FileRepositoryTest extends TestCase
{
    private string $storagePath;

    protected function setUp(): void
    {
        $this->storagePath = sys_get_temp_dir() . '/webauthn_test_storage.txt';
        if (file_exists($this->storagePath)) {
            unlink($this->storagePath);
        }
    }

    protected function tearDown(): void
    {
        if (file_exists($this->storagePath)) {
            unlink($this->storagePath);
        }
        $dir = dirname($this->storagePath);
        if (is_dir($dir)) {
            // Be careful with rmdir in real projects
            @rmdir($dir);
        }
    }

    public function testConstructorCreatesFile()
    {
        $this->assertFileDoesNotExist($this->storagePath);
        new FileRepository($this->storagePath);
        $this->assertFileExists($this->storagePath);
    }

    public function testSaveAndGetById()
    {
        $repository = new FileRepository($this->storagePath);

        $privateKey = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_EC, "curve_name" => "prime256v1"]);
        $credential = new Credential(
            id: base64_encode('cred-123'),
            privateKey: $privateKey,
            rpId: 'integ-test.com',
            userHandle: 'user-handle-456'
        );

        $repository->save($credential);

        // Create a new instance to ensure it reads from the file
        $newRepository = new FileRepository($this->storagePath);
        $retrievedCredential = $newRepository->getById('integ-test.com', base64_encode('cred-123'));

        $this->assertEquals($credential->getId(), $retrievedCredential->getId());
        $this->assertEquals($credential->getRpId(), $retrievedCredential->getRpId());
    }

    public function testGetByIdThrowsExceptionWhenNotFound()
    {
        $this->expectException(CredentialNotFoundException::class);
        $repository = new FileRepository($this->storagePath);
        $repository->getById('integ-test.com', 'not-found-id');
    }
}
