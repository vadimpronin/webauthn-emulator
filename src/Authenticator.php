<?php

namespace WebauthnEmulator;

use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\TextStringObject;
use JetBrains\PhpStorm\ArrayShape;
use JsonException;
use WebauthnEmulator\CredentialRepository\RepositoryInterface;
use WebauthnEmulator\Exceptions\CredentialNotFoundException;
use WebauthnEmulator\Exceptions\InvalidArgumentException;

class Authenticator implements AuthenticatorInterface
{
    public function __construct(
        protected RepositoryInterface $repository
    )
    {
    }

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
    public function getAttestation(array $registerOptions): array
    {
        $credential = $this->createCredential($registerOptions);

        $clientDataJson = json_encode([
            'type' => 'webauthn.create',
            'challenge' => $registerOptions['challenge'],
            'origin' => 'https://' . $credential->getRpId() . '/',
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
            'rawId' => $credential->getId(),
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
    public function getAssertion(string $rpId, string|array|null $credentialIds, string $challenge): array
    {
        $credential = $this->getCredential($rpId, $credentialIds);

        // prepare signature
        $clientDataJson = json_encode([
            'type' => 'webauthn.get',
            'challenge' => $challenge,
            'origin' => 'https://' . $credential->getRpId() . '/',
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $clientDataHash = hash('sha256', $clientDataJson, true);

        $flags = pack('C', 1);
        $authenticatorData = $credential->getRpIdHash() . $flags . $credential->getPackedSignCount();

        openssl_sign($authenticatorData . $clientDataHash, $signature, $credential->privateKey, OPENSSL_ALGO_SHA256);

        return [
            'id' => $credential->getSafeId(),
            'rawId' => $credential->getId(),
            'response' => [
                'authenticatorData' => base64_encode($authenticatorData),
                'clientDataJSON' => base64_encode($clientDataJson),
                'signature' => base64_encode($signature),
                'userHandle' => $credential->getUserHandle(),
            ],
            'type' => 'public-key',
        ];
    }

    protected function createCredential(array $options): CredentialInterface
    {
        $credential = CredentialFactory::makeFromOptions($options);
        $this->repository->save($credential);

        return $credential;
    }

    protected function getCredential(string $rpId, string|array|null $credentialIds): CredentialInterface
    {
        if (is_string($credentialIds)) {
            $credentialIds = [[
                'id' => $credentialIds,
                'type' => 'public-key',
            ]];
        }

        if (is_array($credentialIds)) {
            foreach ($credentialIds as $credentialId) {
                try {
                    $credential = $this->repository->getById($rpId, $credentialId['id']);
                }
                catch (CredentialNotFoundException) {
                    // receive exception if not found, normal case
                    continue;
                }

                return $credential;
            }
        } else {
            try {
                return $this->repository->getById($rpId, null);
            }
            catch (CredentialNotFoundException) {
                // nothing found, normal case
            }
        }

        throw new InvalidArgumentException('Requested rpId and userId do not match any credential');
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
        $authData .= base64_decode($credential->getId());
        $authData .= $credential->getCoseKey();

        return $authData;
    }
}