<?php
/** @noinspection DuplicatedCode */
/** @noinspection PhpUnhandledExceptionInspection */

use GuzzleHttp\Client;
use GuzzleHttp\Cookie\FileCookieJar;
use WebauthnEmulator\Authenticator;
use WebauthnEmulator\CredentialRepository\FileRepository;

require_once __DIR__ . '/../vendor/autoload.php';

$storage = new FileRepository('./key_storage.txt');
$authenticator = new Authenticator($storage);

// pseudo-random username based on hostname
$hostPartialHash = strtolower(substr(md5('webauthn' . gethostname()), 0, 8));
$username = 'test_' . $hostPartialHash;
$uid = $hostPartialHash . '-8801-81f2-8ae6-d1a3ce75e599';
echo "Username: $username\n";
echo "UID: $uid\n";

// Step 0 (get API key)
$config = file_get_contents('https://demo.quado.io/js/config.js');
preg_match("(\['demo.quado.io'[^]]*])", $config, $matches);
$config = json_decode(str_replace("'", '"', $matches[0]));
$apiKey = $config[12];

$httpClient = new Client([
    'cookies' => new FileCookieJar('./cookies.json', true),
    'headers' => [
        'X-Api-Key' => $apiKey,
        'X-Quado-Ext' => 'demo',
    ],
]);


// Registration step 1 (request challenge from server)
$registrationInitUrl = 'https://api.quado.io/webauthn/api/v1/registrations';
$registrationInitRequest = [
    'uid' => $uid,
    'params' => [
        'user' => [
            'name' => $username,
            'displayName' => $username,
        ],
        'authenticatorSelection' => [
            'userVerification' => 'discouraged',
        ],
        'timeout' => 30000,
        'attestation' => 'none',
        'extensions' => new stdClass(),
    ],
];
$registrationInitResponse = $httpClient
    ->post($registrationInitUrl, ['json' => $registrationInitRequest])
    ->getBody()
    ->getContents();
echo "\n\nregistrationInitResponse\n" . json_encode(json_decode($registrationInitResponse), JSON_PRETTY_PRINT) . "\n\n";
$registrationInitResponse = json_decode($registrationInitResponse, true);

/* Example response from quado.io:
{
    "fido_request": {
        "rp": {
            "id": "quado.io",
            "name": "FIDO2 Demo Site",
            "icon": "https:\/\/demo-icon.quado.io"
        },
        "user": {
            "id": "ZmRmMWZiMjUtNjRiYy00OWRjLThjZGYtNGQxMjdjM2JmZDk2",
            "name": "test_9b32c737",
            "displayName": "test_9b32c737"
        },
        "challenge": "SUXdcr3aWvmxzipVGh0az2IGu8rnjjEYofYGOADVx5w",
        "pubKeyCredParams": [
            {
                "type": "public-key",
                "alg": -7
            },
            {
                "type": "public-key",
                "alg": -35
            },
            {
                "type": "public-key",
                "alg": -36
            },
            {
                "type": "public-key",
                "alg": -257
            },
            {
                "type": "public-key",
                "alg": -258
            },
            {
                "type": "public-key",
                "alg": -259
            },
            {
                "type": "public-key",
                "alg": -37
            },
            {
                "type": "public-key",
                "alg": -38
            },
            {
                "type": "public-key",
                "alg": -39
            },
            {
                "type": "public-key",
                "alg": -8
            },
            {
                "type": "public-key",
                "alg": -65535
            }
        ],
        "timeout": 30000,
        "excludeCredentials": [],
        "authenticatorSelection": {
            "userVerification": "discouraged"
        },
        "attestation": "none"
    },
    "transaction_id": "2b60523b-9dde-4388-b25f-3ef916663403"
}
*/

// Generate attestation (response to challenge)
$attestation = $authenticator->getAttestation(
    registerOptions: $registrationInitResponse['fido_request'],
    origin: 'https://demo.quado.io',
    extra: [
        'crossOrigin' => false,
        'other_keys_can_be_added_here' => 'do not compare clientDataJSON against a template. See https://goo.gl/yabPex',
    ]
);
echo "\n\nattestation\n" . json_encode($attestation, JSON_PRETTY_PRINT) . "\n\n";

/* Example attestation:

{
    "id": "HB_PkyggPmHCHbcYyQCfLXTakdmq3WGCcOBjLQK3WkA",
    "rawId": "HB\/PkyggPmHCHbcYyQCfLXTakdmq3WGCcOBjLQK3WkA=",
    "response": {
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiU1VYZGNyM2FXdm14emlwVkdoMGF6MklHdThybmpqRVlvZllHT0FEVng1dyIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby5xdWFkby5pbyJ9",
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikE4Mf1Uogz5Gwtvu4tANTrL1cSUjdn5CvDL8Kk18IGJNBAAAAAAAAAAAAAAAAAAAAAAAAAAAAIBwfz5MoID5hwh23GMkAny102pHZqt1hgnDgYy0Ct1pApQECAyYgASFYIKtDh5QfXUsfsbPweWBRksPqy+nLBf4TE31nnNHeMNBuIlgg5ygeMxKRIeFY9wEj91E96EPb0LwdPCO3X\/55MdCy4kw="
    },
    "type": "public-key"
}

*/


// Registration step 2 (send attestation to server)
$registrationFinishUrl = 'https://api.quado.io/webauthn/api/v1/registrations';
$registrationFinishRequest = [
    'fido_response' => Authenticator::base64Normal2Url($attestation),
];

$registrationFinishResponse = $httpClient
    ->patch($registrationFinishUrl, ['json' => $registrationFinishRequest])
    ->getBody()
    ->getContents();
echo "\n\nregistrationFinishResponse\n" . json_encode(json_decode($registrationFinishResponse), JSON_PRETTY_PRINT) . "\n\n";
$registrationFinishResponse = json_decode($registrationFinishResponse, true);

/* Example response:
{
    "uid": "9b32c737-8801-81f2-8ae6-d1a3ce75e599",
    "transaction_id": "fb8fd33e-6a9f-475b-8661-659181cd995c",
    "key_info": {
        "id": "849fec7e-83cc-4668-9aa6-4680e95bdfda",
        "user_id": "",
        "counter": 0,
        "aaguid": "00000000-0000-0000-0000-000000000000",
        "credential_id": "HB_PkyggPmHCHbcYyQCfLXTakdmq3WGCcOBjLQK3WkA",
        "attestation_type": "None",
        "attestation_format": "none",
        "created_at": "2023-12-28T12:33:20.929951531Z",
        "updated_at": "2023-12-28T12:33:20.929951531Z"
    },
    "client_info": {
        "type": "webauthn.create",
        "challenge": "SUXdcr3aWvmxzipVGh0az2IGu8rnjjEYofYGOADVx5w",
        "origin": "https:\/\/demo.quado.io",
        "tokenBinding": null
    },
    "attestation_info": {
        "attStmt": {},
        "attTrustPath": [],
        "attType": "None",
        "authData": {
            "counter": 0,
            "credential": {
                "aaguid": "00000000-0000-0000-0000-000000000000",
                "cose": {
                    "alg": -7,
                    "crv": 1,
                    "kty": 2,
                    "x": "q0OHlB9dSx+xs\/B5YFGSw+rL6csF\/hMTfWec0d4w0G4=",
                    "y": "5ygeMxKRIeFY9wEj91E96EPb0LwdPCO3X\/55MdCy4kw="
                },
                "credentialID": "HB_PkyggPmHCHbcYyQCfLXTakdmq3WGCcOBjLQK3WkA"
            },
            "extensions": null,
            "flags": {
                "AT": true,
                "ED": false,
                "RFU1": false,
                "RFU21": false,
                "RFU22": false,
                "RFU23": false,
                "UP": true,
                "UV": true
            },
            "rpHash": "E4Mf1Uogz5Gwtvu4tANTrL1cSUjdn5CvDL8Kk18IGJM"
        },
        "fmt": "none"
    },
    "transports": null
}

 */

if ($registrationFinishResponse['uid'] === $uid) {
    echo "User $username registered successfully\n";
}
