<?php

namespace WebauthnEmulator\Tests\Unit;

use JsonException;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use WebauthnEmulator\Authenticator;
use WebauthnEmulator\Credential;
use WebauthnEmulator\CredentialInterface;
use WebauthnEmulator\CredentialRepository\RepositoryInterface;
use WebauthnEmulator\Exceptions\CredentialNotFoundException;
use WebauthnEmulator\Exceptions\InvalidArgumentException;

class AuthenticatorTest extends TestCase
{
    private MockObject|RepositoryInterface $repositoryMock;
    private Authenticator $authenticator;

    protected function setUp(): void
    {
        $this->repositoryMock = $this->createMock(RepositoryInterface::class);
        $this->authenticator = new Authenticator($this->repositoryMock);
    }

    /**
     * @throws JsonException
     */
    public function testGetAttestation()
    {
        $options = [
            'rp' => ['id' => 'localhost', 'name' => 'Test Site'],
            'user' => ['id' => base64_encode('user-id'), 'name' => 'test', 'displayName' => 'Test User'],
            'challenge' => 'some-random-challenge-string',
            'pubKeyCredParams' => [['alg' => -7, 'type' => 'public-key']],
            'attestation' => 'none',
        ];

        $this->repositoryMock
            ->expects($this->once())
            ->method('save')
            ->with($this->isInstanceOf(CredentialInterface::class));

        $result = $this->authenticator->getAttestation($options);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('id', $result);
        $this->assertArrayHasKey('rawId', $result);
        $this->assertArrayHasKey('response', $result);
        $this->assertArrayHasKey('clientDataJSON', $result['response']);

        $clientData = json_decode(base64_decode($result['response']['clientDataJSON']), true);
        $this->assertSame('webauthn.create', $clientData['type']);
        $this->assertSame($options['challenge'], $clientData['challenge']);
        $this->assertSame('https://localhost', $clientData['origin']);
    }

    /**
     * @throws JsonException
     */
    public function testGetAssertionSuccess()
    {
        $rpId = 'localhost';
        $credentialId = base64_encode('some-cred-id');
        $challenge = 'some-auth-challenge';

        $privateKey = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_EC, "curve_name" => "prime256v1"]);
        $credential = new Credential($credentialId, $privateKey, $rpId, 'user-handle', 0);

        $this->repositoryMock
            ->expects($this->once())
            ->method('getById')
            ->with($rpId, $credentialId)
            ->willReturn($credential);

        $this->repositoryMock
            ->expects($this->once())
            ->method('save')
            ->with($this->callback(fn($cred) => $cred->signCount === 1));

        $result = $this->authenticator->getAssertion($rpId, [['id' => $credentialId]], $challenge);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('id', $result);
        $this->assertArrayHasKey('rawId', $result);
        $this->assertArrayHasKey('response', $result);
        $this->assertArrayHasKey('signature', $result['response']);

        $clientData = json_decode(base64_decode($result['response']['clientDataJSON']), true);
        $this->assertSame('webauthn.get', $clientData['type']);
        $this->assertSame($challenge, $clientData['challenge']);
    }

    /**
     * @throws JsonException
     */
    public function testGetAssertionThrowsWhenNoCredentialFound()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Requested rpId and credentialId(s) not found in the repository');

        $rpId = 'localhost';
        $credentialId = base64_encode('non-existent-cred-id');

        $this->repositoryMock
            ->expects($this->once())
            ->method('getById')
            ->with($rpId, $credentialId)
            ->willThrowException(new CredentialNotFoundException());

        $this->authenticator->getAssertion($rpId, [['id' => $credentialId]], 'challenge');
    }

    /**
     * @throws JsonException
     */
    public function testGetAssertionWithSingleStringCredentialId()
    {
        $rpId = 'localhost';
        $credentialId = 'some-cred-id-string';
        $credentialIdBase64 = base64_encode($credentialId);
        $challenge = 'some-auth-challenge';
        $privateKey = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_EC, "curve_name" => "prime256v1"]);
        $credential = new Credential($credentialIdBase64, $privateKey, $rpId, 'user-handle', 0);
        $this->repositoryMock
            ->expects($this->once())
            ->method('getById')
            ->with($rpId, $credentialIdBase64) // The authenticator converts the ID to raw before calling the repo
            ->willReturn($credential);
        $this->repositoryMock
            ->expects($this->once())
            ->method('save');
        $result = $this->authenticator->getAssertion($rpId, $credentialIdBase64, $challenge);
        $this->assertIsArray($result);
        $this->assertArrayHasKey('id', $result);
    }

    /**
     * @throws JsonException
     */
    public function testGetAssertionWithNullCredentialId()
    {
        $rpId = 'localhost';
        $challenge = 'some-auth-challenge';
        $privateKey = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_EC, "curve_name" => "prime256v1"]);
        $credential = new Credential(base64_encode('cred-id'), $privateKey, $rpId, 'user-handle', 0);
        $this->repositoryMock
            ->expects($this->once())
            ->method('get')
            ->with($rpId)
            ->willReturn([$credential]);
        $result = $this->authenticator->getAssertion($rpId, null, $challenge);
        $this->assertIsArray($result);
        $this->assertSame(1, $credential->signCount);
    }

}
