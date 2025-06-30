<?php

namespace WebauthnEmulator\Tests\Integration;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use WebauthnEmulator\Credential;
use WebauthnEmulator\CredentialRepository\RepositoryInterface;
use WebauthnEmulator\Exceptions\CredentialNotFoundException;

abstract class AbstractRepositoryTest extends TestCase
{
    /**
     * Creates a fresh instance of the repository implementation being tested.
     */
    abstract protected function createRepository(): RepositoryInterface;

    /**
     * Helper to create a credential instance for tests.
     */
    protected function createCredential(string $id, string $rpId, string $userHandle, int $signCount = 0): Credential
    {
        $privateKey = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_EC, "curve_name" => "prime256v1"]);
        if ($privateKey === false) {
            throw new RuntimeException('Failed to create private key');
        }

        return new Credential(
            id: base64_encode($id),
            privateKey: $privateKey,
            rpId: $rpId,
            userHandle: $userHandle,
            signCount: $signCount
        );
    }

    // --- In-Memory Behavior / Caching Tests ---

    /**
     * Verifies that getById() returns the exact same object instance that was saved,
     * confirming in-memory caching behavior.
     */
    public function testSaveAndGetByIdReturnsSameInstance()
    {
        $repository = $this->createRepository();
        $credential = $this->createCredential('cred-123', 'integ-test.com', 'user-handle-456');

        $repository->save($credential);

        $retrievedCredential = $repository->getById('integ-test.com', base64_encode('cred-123'));

        $this->assertSame($credential, $retrievedCredential);
    }

    /**
     * Verifies that get() returns an array containing the exact same object instances
     * that were saved, confirming in-memory caching.
     */
    public function testGetReturnsAllCredentialsForRpIdWithSameInstances()
    {
        $repository = $this->createRepository();
        $credential1 = $this->createCredential('cred-123', 'integ-test.com', 'user-1');
        $credential2 = $this->createCredential('cred-789', 'integ-test.com', 'user-2');

        $repository->save($credential1);
        $repository->save($credential2);

        $credentials = $repository->get('integ-test.com');

        $this->assertCount(2, $credentials);
        $this->assertSame($credential1, $credentials[base64_encode('cred-123')]);
        $this->assertSame($credential2, $credentials[base64_encode('cred-789')]);
    }

    /**
     * Ensures credentials for one RP ID are not accessible via another RP ID
     * within the same repository instance.
     */
    public function testMultipleRpIdsAreIsolated()
    {
        $repository = $this->createRepository();
        $credential1 = $this->createCredential('cred-1', 'site1.com', 'user-1');
        $credential2 = $this->createCredential('cred-2', 'site2.com', 'user-2');

        $repository->save($credential1);
        $repository->save($credential2);

        $site1Credentials = $repository->get('site1.com');
        $site2Credentials = $repository->get('site2.com');

        $this->assertCount(1, $site1Credentials);
        $this->assertCount(1, $site2Credentials);
        $this->assertArrayHasKey(base64_encode('cred-1'), $site1Credentials);
        $this->assertArrayHasKey(base64_encode('cred-2'), $site2Credentials);
    }


    // --- Persistence Behavior Tests ---

    /**
     * Verifies that a saved credential can be retrieved by a new repository instance,
     * confirming data is successfully persisted.
     */
    public function testSaveAndGetByIdWithPersistence()
    {
        $repository = $this->createRepository();
        $credential = $this->createCredential('cred-123', 'integ-test.com', 'user-handle-456');

        $repository->save($credential);

        // Create a new instance to ensure it reads saved data
        $newRepository = $this->createRepository();
        $retrievedCredential = $newRepository->getById('integ-test.com', base64_encode('cred-123'));

        $this->assertEquals($credential->getId(), $retrievedCredential->getId());
        $this->assertEquals($credential->getRpId(), $retrievedCredential->getRpId());
        $this->assertEquals($credential->getUserHandle(), $retrievedCredential->getUserHandle());
        $this->assertEquals($credential->signCount, $retrievedCredential->signCount);
    }

    /**
     * Verifies that multiple saved credentials for one RP ID can be retrieved by
     * a new repository instance.
     */
    public function testGetReturnsAllCredentialsForRpIdWithPersistence()
    {
        $repository = $this->createRepository();
        $credential1 = $this->createCredential('cred-123', 'integ-test.com', 'user-1');
        $credential2 = $this->createCredential('cred-789', 'integ-test.com', 'user-2');

        $repository->save($credential1);
        $repository->save($credential2);

        // Re-load the repository to ensure it reads saved data
        $newRepository = $this->createRepository();
        $credentials = $newRepository->get('integ-test.com');

        $this->assertCount(2, $credentials);
        $this->assertArrayHasKey(base64_encode('cred-123'), $credentials);
        $this->assertArrayHasKey(base64_encode('cred-789'), $credentials);
    }

    /**
     * Verifies that the isolation between RP IDs is maintained across
     * different repository instances.
     */
    public function testMultipleRpIdsAreIsolatedWithPersistence()
    {
        $repository = $this->createRepository();
        $credential1 = $this->createCredential('cred-1', 'site1.com', 'user-1');
        $credential2 = $this->createCredential('cred-2', 'site2.com', 'user-2');

        $repository->save($credential1);
        $repository->save($credential2);

        // Re-load the repository to ensure it reads saved data
        $newRepository = $this->createRepository();
        $site1Credentials = $newRepository->get('site1.com');
        $site2Credentials = $newRepository->get('site2.com');

        $this->assertCount(1, $site1Credentials);
        $this->assertCount(1, $site2Credentials);
        $this->assertArrayHasKey(base64_encode('cred-1'), $site1Credentials);
        $this->assertArrayHasKey(base64_encode('cred-2'), $site2Credentials);
    }

    /**
     * Verifies that updating a credential (e.g., its signCount) and re-saving it
     * correctly persists the changes.
     */
    public function testUpdateExistingCredential()
    {
        $repository = $this->createRepository();
        $credential = $this->createCredential('cred-update', 'rp-update', 'user-update');
        $repository->save($credential);

        $credential->incrementSignCount();
        $repository->save($credential);

        // Re-load the repository to ensure it reads saved data
        $newRepository = $this->createRepository();
        $retrieved = $newRepository->getById('rp-update', base64_encode('cred-update'));

        $this->assertSame(1, $retrieved->signCount);
    }

    // --- Edge Cases and API Contract Tests ---

    public function testGetByIdThrowsExceptionWhenNotFound()
    {
        $this->expectException(CredentialNotFoundException::class);
        $repository = $this->createRepository();
        $repository->getById('integ-test.com', 'not-found-id');
    }

    public function testGetReturnsEmptyArrayForUnknownRpId()
    {
        $repository = $this->createRepository();
        $credentials = $repository->get('unknown-rp.com');
        $this->assertIsArray($credentials);
        $this->assertEmpty($credentials);
    }

    public function testFluentInterface()
    {
        $repository = $this->createRepository();
        $credential = $this->createCredential('cred-fluent', 'rp-fluent', 'user-fluent');

        $result = $repository->save($credential);

        $this->assertSame($repository, $result);
    }
}

