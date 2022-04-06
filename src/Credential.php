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

        // RFC 8152
        return (string)MapObject::create([
            MapItem::create(
                UnsignedIntegerObject::create(1), // kty (Identification of the key type)
                UnsignedIntegerObject::create(2) // EC2 (Elliptic Curve Keys w/ x- and y-coordinate pair)
            ),
            MapItem::create(
                UnsignedIntegerObject::create(3), // alg (Key usage restriction to this algorithm)
                NegativeIntegerObject::create(-7) // ES256 (ECDSA w/ SHA-256)
            ),
            MapItem::create(
                NegativeIntegerObject::create(-1), // crv (EC identifier - Taken from the "COSE Elliptic Curves" registry)
                UnsignedIntegerObject::create(1)  // P-256 (NIST P-256 also known as secp256r1)
            ),
            MapItem::create(
                NegativeIntegerObject::create(-2), // x-coordinate
                ByteStringObject::create($keyDetails['ec']['x'])
            ),
            MapItem::create(
                NegativeIntegerObject::create(-3), // y-coordinate
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
        return pack('n', strlen(base64_decode($this->id)));
    }

    public function getSafeId(): string
    {
        $safeId = strtr($this->id, '+/', '-_');
        return rtrim($safeId, '=');
    }

    #[ArrayShape(['id' => "string", 'privateKey' => "string", 'rpId' => "string", 'userHandle' => "string", 'signCount' => "int"])]
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