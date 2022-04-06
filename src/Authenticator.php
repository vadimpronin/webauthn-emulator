<?php

/** @noinspection PhpUnused */

namespace WebauthnEmulator;

use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\TextStringObject;
use JetBrains\PhpStorm\ArrayShape;
use JsonException;

class Authenticator
{
    /**
     * @throws JsonException
     */
    #[ArrayShape([
        'id' => "string",
        'rawId' => "string",
        'response' => [
            'clientDataJSON' => "string",
            'attestationObject' => "string"
        ],
        'type' => "string"
    ])]
    public function getAttestation(CredentialInterface $credential, string $challenge): array
    {
        $clientDataJson = json_encode([
            'type' => 'webauthn.create',
            'challenge' => $challenge,
            'origin' => 'https://'.$credential->getRpId().'/',
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        $attestationObject = new MapObject([
            'fmt' => new MapItem(new TextStringObject('fmt'), new TextStringObject('none')),
            'attStmt' => new MapItem(new TextStringObject('attStmt'), new MapObject()),
            'authData' => new MapItem(
                new TextStringObject('authData'),
                new ByteStringObject($this->getAuthData($credential))
            ),
        ]);

        return [
            'id' => $credential->getSafeId(),
            'rawId' => $credential->id,
            'response' => [
                'clientDataJSON' => base64_encode($clientDataJson),
                'attestationObject' => base64_encode((string)$attestationObject),
            ],
            'type' => 'public-key',
        ];
    }

    /**
     * @throws JsonException
     */
    #[ArrayShape(['id' => "string", 'rawId' => "string", 'response' => ['authenticatorData' => "string", 'clientDataJSON' => "string", 'signature' => "string", 'userHandle' => "string"], 'type' => "string"])]
    public function getAssertion(CredentialInterface $credential, string $challenge): array
    {
        // prepare signature
        $clientDataJson = json_encode([
              'type' => 'webauthn.get',
              'challenge' => $challenge,
              'origin' => 'https://'.$credential->getRpId().'/',
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $clientDataHash = hash('sha256', $clientDataJson, true);

        $flags = pack('C', 1);
        $authenticatorData = $credential->getRpIdHash() . $flags . $credential->getPackedSignCount();

        openssl_sign($authenticatorData . $clientDataHash, $signature, $credential->privateKey, OPENSSL_ALGO_SHA256);

        return [
            'id' => $credential->getSafeId(),
            'rawId' => $credential->id,
            'response' => [
                'authenticatorData' => base64_encode($authenticatorData),
                'clientDataJSON' => base64_encode($clientDataJson),
                'signature' => base64_encode($signature),
                'userHandle' => $credential->userHandle,
            ],
            'type' => 'public-key',
        ];
    }

    protected function getAuthData(Credential $credential): string
    {
        $flags = pack('C', 65);  // attested_data + user_present
        $aaGuid = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

        $authData = $credential->getRpIdHash();
        $authData .= $flags;
        $authData .= $credential->getPackedSignCount();
        $authData .= $aaGuid;
        $authData .= $credential->getPackedIdLength();
        $authData .= base64_decode($credential->id);
        $authData .= $credential->getCoseKey();

        return $authData;
    }
}