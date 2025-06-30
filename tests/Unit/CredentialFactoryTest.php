<?php

namespace WebauthnEmulator\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebauthnEmulator\CredentialFactory;
use WebauthnEmulator\CredentialInterface;
use WebauthnEmulator\Exceptions\InvalidArgumentException;

class CredentialFactoryTest extends TestCase
{
    private function getValidOptions(): array
    {
        return [
            'rp' => ['id' => 'example.com', 'name' => 'Example Corp'],
            'user' => ['id' => 'some-user-id', 'name' => 'user', 'displayName' => 'User'],
            'challenge' => 'some-challenge',
            'pubKeyCredParams' => [['alg' => -7, 'type' => 'public-key']],
            'attestation' => 'none',
        ];
    }

    public function testMakeFromOptionsSuccess()
    {
        $options = $this->getValidOptions();
        $credential = CredentialFactory::makeFromOptions($options);

        /** @noinspection PhpConditionAlreadyCheckedInspection */
        $this->assertInstanceOf(CredentialInterface::class, $credential);
        $this->assertSame('example.com', $credential->getRpId());
        $this->assertSame('some-user-id', $credential->getUserHandle());
    }

    public function testThrowsForMissingRp()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Missing "rp" or "user" data');

        $options = $this->getValidOptions();
        unset($options['rp']);
        CredentialFactory::makeFromOptions($options);
    }

    public function testThrowsForUnsupportedAlgorithm()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Requested pubKeyCredParams does not contain supported type. Only ES256 (alg: -7) is supported at the moment.');

        $options = $this->getValidOptions();
        $options['pubKeyCredParams'] = [['alg' => -257, 'type' => 'public-key']];
        CredentialFactory::makeFromOptions($options);
    }

    public function testThrowsForUnsupportedAttestation()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Only "none" attestation supported');

        $options = $this->getValidOptions();
        $options['attestation'] = 'packed';
        CredentialFactory::makeFromOptions($options);
    }
}
