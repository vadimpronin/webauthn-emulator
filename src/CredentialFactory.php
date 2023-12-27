<?php

namespace WebauthnEmulator;

use WebauthnEmulator\Exceptions\InvalidArgumentException;

class CredentialFactory
{
    public static function makeFromOptions(array $options): CredentialInterface
    {
        if (empty($options['pubKeyCredParams']) || !in_array(['alg' => -7, 'type' => 'public-key'], $options['pubKeyCredParams'])) {
            throw new InvalidArgumentException('Requested pubKeyCredParams does not contain supported type. Only ES256 (alg: -7) is supported at the moment.');
        }

        if (!empty($options['attestation']) && $options['attestation'] !== 'none') {
            throw new InvalidArgumentException('Only "none" attestation supported');
        }

        return new Credential(
            id: base64_encode(string: openssl_random_pseudo_bytes(32)),
            privateKey: openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_EC, "curve_name" => "prime256v1"]),
            rpId: $options['rp']['id'],
            userHandle: $options['user']['id'],
        );
    }

    public static function makeFromArray(array $data): CredentialInterface
    {
        return Credential::fromArray($data);
    }
}

