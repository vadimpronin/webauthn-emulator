<?php

namespace WebauthnEmulator\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebauthnEmulator\Credential;

class CredentialTest extends TestCase
{
    private Credential $credential;

    protected function setUp(): void
    {
        $privateKey = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_EC, "curve_name" => "prime256v1"]);
        $this->credential = new Credential(
            id: base64_encode('credential-id'),
            privateKey: $privateKey,
            rpId: 'test.com',
            userHandle: base64_encode('user-handle'),
            signCount: 10
        );
    }

    public function testIncrementSignCount()
    {
        $this->assertSame(10, $this->credential->signCount);
        $this->credential->incrementSignCount();
        $this->assertSame(11, $this->credential->signCount);
    }

    public function testGetRpIdHash()
    {
        $this->assertSame(hash('sha256', 'test.com', true), $this->credential->getRpIdHash());
    }

    public function testGetPackedSignCount()
    {
        $this->assertSame(pack('N', 10), $this->credential->getPackedSignCount());
    }

    public function testSerialization()
    {
        $serialized = serialize($this->credential);
        /** @var Credential $unserialized */
        $unserialized = unserialize($serialized);

        $this->assertInstanceOf(Credential::class, $unserialized);
        $this->assertEquals($this->credential->getId(), $unserialized->getId());
        $this->assertEquals($this->credential->getRpId(), $unserialized->getRpId());
        $this->assertEquals($this->credential->signCount, $unserialized->signCount);
    }

    public function testToArrayAndFromArray()
    {
        $data = $this->credential->toArray();
        $newCredential = Credential::fromArray($data);

        $this->assertEquals($this->credential->getId(), $newCredential->getId());
        $this->assertEquals($this->credential->getRpId(), $newCredential->getRpId());
        $this->assertEquals($this->credential->signCount, $newCredential->signCount);
    }
}
