<?php

namespace WebauthnEmulator\Tests\Integration;

use PHPUnit\Framework\TestCase;
use WebauthnEmulator\Credential;
use WebauthnEmulator\CredentialRepository\InMemoryRepository;
use WebauthnEmulator\Exceptions\CredentialNotFoundException;

class InMemoryRepositoryTest extends TestCase
{
    private InMemoryRepository $repository;

    protected function setUp(): void
    {
        $this->repository = new InMemoryRepository();
    }

    public function testSaveAndGetById()
    {
        $privateKey = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_EC, "curve_name" => "prime256v1"]);
        $credential = new Credential(
            id: base64_encode('cred-123'),
            privateKey: $privateKey,
            rpId: 'integ-test.com',
            userHandle: 'user-handle-456'
        );

        $this->repository->save($credential);

        $retrievedCredential = $this->repository->getById('integ-test.com', base64_encode('cred-123'));

        $this->assertEquals($credential->getId(), $retrievedCredential->getId());
        $this->assertEquals($credential->getRpId(), $retrievedCredential->getRpId());
        $this->assertSame($credential, $retrievedCredential); // In-memory should return the same instance
    }

    public function testGetByIdThrowsExceptionWhenNotFound()
    {
        $this->expectException(CredentialNotFoundException::class);
        $this->repository->getById('integ-test.com', 'not-found-id');
    }

    public function testGetReturnsEmptyArrayForUnknownRpId()
    {
        $credentials = $this->repository->get('unknown-rp.com');
        $this->assertIsArray($credentials);
        $this->assertEmpty($credentials);
    }

    public function testGetReturnsAllCredentialsForRpId()
    {
        $privateKey1 = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_EC, "curve_name" => "prime256v1"]);
        $privateKey2 = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_EC, "curve_name" => "prime256v1"]);
        
        $credential1 = new Credential(
            id: base64_encode('cred-123'),
            privateKey: $privateKey1,
            rpId: 'integ-test.com',
            userHandle: 'user-handle-456'
        );
        
        $credential2 = new Credential(
            id: base64_encode('cred-789'),
            privateKey: $privateKey2,
            rpId: 'integ-test.com',
            userHandle: 'user-handle-789'
        );

        $this->repository->save($credential1);
        $this->repository->save($credential2);

        $credentials = $this->repository->get('integ-test.com');
        
        $this->assertCount(2, $credentials);
        $this->assertArrayHasKey(base64_encode('cred-123'), $credentials);
        $this->assertArrayHasKey(base64_encode('cred-789'), $credentials);
        $this->assertSame($credential1, $credentials[base64_encode('cred-123')]);
        $this->assertSame($credential2, $credentials[base64_encode('cred-789')]);
    }

    public function testMultipleRpIdsAreIsolated()
    {
        $privateKey1 = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_EC, "curve_name" => "prime256v1"]);
        $privateKey2 = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_EC, "curve_name" => "prime256v1"]);
        
        $credential1 = new Credential(
            id: base64_encode('cred-123'),
            privateKey: $privateKey1,
            rpId: 'site1.com',
            userHandle: 'user-1'
        );
        
        $credential2 = new Credential(
            id: base64_encode('cred-456'),
            privateKey: $privateKey2,
            rpId: 'site2.com',
            userHandle: 'user-2'
        );

        $this->repository->save($credential1);
        $this->repository->save($credential2);

        $site1Credentials = $this->repository->get('site1.com');
        $site2Credentials = $this->repository->get('site2.com');

        $this->assertCount(1, $site1Credentials);
        $this->assertCount(1, $site2Credentials);
        $this->assertArrayHasKey(base64_encode('cred-123'), $site1Credentials);
        $this->assertArrayHasKey(base64_encode('cred-456'), $site2Credentials);
    }

    public function testFluentInterface()
    {
        $privateKey = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_EC, "curve_name" => "prime256v1"]);
        $credential = new Credential(
            id: base64_encode('cred-123'),
            privateKey: $privateKey,
            rpId: 'integ-test.com',
            userHandle: 'user-handle-456'
        );

        $result = $this->repository->save($credential);
        
        $this->assertSame($this->repository, $result);
    }

    public function testDataPersistenceWithinSameInstance()
    {
        $privateKey = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_EC, "curve_name" => "prime256v1"]);
        $credential = new Credential(
            id: base64_encode('cred-persist'),
            privateKey: $privateKey,
            rpId: 'persist-test.com',
            userHandle: 'user-persist'
        );

        $this->repository->save($credential);
        
        // Data should persist within the same instance
        $retrieved1 = $this->repository->getById('persist-test.com', base64_encode('cred-persist'));
        $retrieved2 = $this->repository->getById('persist-test.com', base64_encode('cred-persist'));
        
        $this->assertSame($retrieved1, $retrieved2);
        $this->assertSame($credential, $retrieved1);
    }

    public function testDataIsNotSharedBetweenInstances()
    {
        $privateKey = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_EC, "curve_name" => "prime256v1"]);
        $credential = new Credential(
            id: base64_encode('cred-isolated'),
            privateKey: $privateKey,
            rpId: 'isolated-test.com',
            userHandle: 'user-isolated'
        );

        $this->repository->save($credential);
        
        // Create a new instance - it should not have the credential
        $newRepository = new InMemoryRepository();
        
        $this->expectException(CredentialNotFoundException::class);
        $newRepository->getById('isolated-test.com', base64_encode('cred-isolated'));
    }
}