<?php

namespace WebauthnEmulator;

use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\TextStringObject;
use InvalidArgumentException;
use JetBrains\PhpStorm\ArrayShape;

class Authenticator
{
    /** @var Credential[][] */
    public array $credentialStorage = [];

    public function __construct(?string $credentialStorageDump = null)
    {
        if (!empty($credentialStorageDump)) {
            $this->restoreCredentialStorage($credentialStorageDump);
        }
    }

    public function addCredential(Credential $credential)
    {
        $this->credentialStorage[$credential->rpId][$credential->id] = $credential;
    }

    #[ArrayShape(['id' => "string", 'rawId' => "string", 'response' => ['clientDataJSON' => "string", 'attestationObject' => "string"], 'type' => "string"])]
    public function makeCredential(array $options): array
    {
        if (empty($options['pubKeyCredParams']) || !in_array(['alg' => -7, 'type' => 'public-key'], $options['pubKeyCredParams'])) {
            throw new InvalidArgumentException('Requested pubKeyCredParams does not contain supported type');
        }

        if (!empty($options['attestation']) && $options['attestation'] != 'none') {
            throw new InvalidArgumentException('Only "none" attestation supported');
        }

        $credential = new Credential(
            id: base64_encode(openssl_random_pseudo_bytes(32)),
            privateKey: openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_EC, "curve_name" => "prime256v1"]),
            rpId: $options['rp']['id'],
            userHandle: $options['user']['id'],
        );

        $this->addCredential($credential);

        $clientDataJson = json_encode([
            'type' => 'webauthn.create',
            'challenge' => $options['challenge'],
            'origin' => 'https://' . $options['rp']['id'] . '/',
        ], JSON_UNESCAPED_SLASHES);

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

    #[ArrayShape(['id' => "string", 'rawId' => "string", 'response' => ['authenticatorData' => "string", 'clientDataJSON' => "string", 'signature' => "string", 'userHandle' => "string"], 'type' => "string"])]
    public function getAssertion(array $options): array
    {
        $credential = $this->getCredential($options['rpId'], $options['allowCredentials'] ?? null);

        $credential->signCount++;

        // prepare signature
        $clientDataJson = json_encode([
            'type' => 'webauthn.get',
            'challenge' => $options['challenge'],
            'origin' => 'https://' . $options['rpId'] . '/',
        ], JSON_UNESCAPED_SLASHES);
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

    protected function getCredential(string $rpId, string|array|null $credentialIds): Credential
    {
        if (is_string($credentialIds)) {
            $credentialIds = [
                'id' => $credentialIds,
                'type' => 'public-key',
            ];
        }

        if (is_array($credentialIds)) {
            foreach ($credentialIds as $credentialId) {
                if (!empty($this->credentialStorage[$rpId][$credentialId['id']])) {
                    return $this->credentialStorage[$rpId][$credentialId['id']];
                }
            }
        } else if (!empty($this->credentialStorage[$rpId])) {
            return reset($this->credentialStorage[$rpId]);
        }

        throw new InvalidArgumentException('Requested rpId and userId do not match any credential');
    }

    public function dumpCredentialStorage(): string
    {
        $storage = [];
        foreach ($this->credentialStorage as $rpCredentials) {
            foreach ($rpCredentials as $credential) {
                $storage[] = $credential->toArray();
            }
        }

        return json_encode($storage);
    }

    public function restoreCredentialStorage($storage)
    {
        $storage = json_decode($storage, true);

        foreach ($storage as $credentialData) {
            $this->addCredential(Credential::fromArray($credentialData));
        }
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