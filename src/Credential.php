<?php

namespace WebauthnEmulator;

use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\UnsignedIntegerObject;
use JetBrains\PhpStorm\ArrayShape;
use OpenSSLAsymmetricKey;

class Credential
{

    public function __construct(
        public string               $id,
        public OpenSSLAsymmetricKey $privateKey,
        public string               $rpId,
        public string               $userHandle,
        public int                  $signCount = 0
    )
    {
    }

    public function getCoseKey(): string
    {
        $keyDetails = openssl_pkey_get_details($this->privateKey);

        return (string)MapObject::create([
            MapItem::create(
                UnsignedIntegerObject::create(1), // TYPE
                UnsignedIntegerObject::create(2) // TYPE_EC2
            ),
            MapItem::create(
                UnsignedIntegerObject::create(3), // ALG
                NegativeIntegerObject::create(-7) // COSE_ALGORITHM_ES256
            ),
            MapItem::create(
                NegativeIntegerObject::create(-1), // DATA_CURVE
                UnsignedIntegerObject::create(1)  // CURVE_P256
            ),
            MapItem::create(
                NegativeIntegerObject::create(-2), // DATA_X
                ByteStringObject::create($keyDetails['ec']['x'])
            ),
            MapItem::create(
                NegativeIntegerObject::create(-3), // DATA_Y
                ByteStringObject::create($keyDetails['ec']['y'])
            ),
        ]);
    }

    public function getRpIdHash(): string
    {
        return hash('sha256', $this->rpId, true);
    }

    public function getPackedSignCount(): string
    {
        return pack('N', $this->signCount);
    }

    public function getPackedIdLength(): string
    {
        return pack('n', mb_strlen(base64_decode($this->id), '8bit'));
    }

    public function getSafeId(): string
    {
        $safeId = strtr($this->id, '+/', '-_');
        return rtrim($safeId, '=');
    }

    #[ArrayShape(['id' => "string", 'privateKey' => "", 'rpId' => "string", 'userHandle' => "string", 'signCount' => "int"])]
    public function toArray(): array
    {
        openssl_pkey_export($this->privateKey, $privateKey);

        return [
            'id' => $this->id,
            'privateKey' => $privateKey,
            'rpId' => $this->rpId,
            'userHandle' => $this->userHandle,
            'signCount' => $this->signCount,
        ];
    }

    public static function fromArray(array $credentialData): static
    {
        return new static(
            id: $credentialData['id'],
            privateKey: openssl_pkey_get_private($credentialData['privateKey']),
            rpId: $credentialData['rpId'],
            userHandle: $credentialData['userHandle'],
            signCount: $credentialData['signCount'],
        );
    }
}