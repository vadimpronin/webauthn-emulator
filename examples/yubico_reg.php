<?php

use GuzzleHttp\Client;
use GuzzleHttp\Cookie\FileCookieJar;
use WebauthnEmulator\Authenticator;
use WebauthnEmulator\CredentialRepository\FileRepository;

require_once __DIR__ . '/../vendor/autoload.php';

$storage = new FileRepository('./key_storage.json');

$httpClient = new Client([
    'cookies' => new FileCookieJar('./cookies.json', TRUE),
]);

$authenticator = new Authenticator($storage);


// Registration step 1 (request challenge from server)
$registrationInitUrl = 'https://demo.yubico.com/api/v1/simple/webauthn/register-begin';
$registrationInitRequest = new stdClass();
$registrationInitResponse = $httpClient
    ->post($registrationInitUrl, ['json' => $registrationInitRequest])
    ->getBody()
    ->getContents();
$registrationInitResponse = json_decode($registrationInitResponse, true);

/* Example response from Yubico demo server:
{
    "data": {
        "displayName": "Yubico demo user",
        "publicKey": {
            "attestation": "direct",
            "authenticatorSelection": {
                "requireResidentKey": false,
                "residentKey": "discouraged",
                "userVerification": "discouraged"
            },
            "challenge": {
                "$base64": "hyb+EYjogAdsDyk36waHO4\/sEEexjxMubvvITc6xtaE="
            },
            "excludeCredentials": [],
            "pubKeyCredParams": [
                {
                    "alg": -7,
                    "type": "public-key"
                },
                {
                    "alg": -257,
                    "type": "public-key"
                }
            ],
            "rp": {
                "id": "demo.yubico.com",
                "name": "Yubico Demo"
            },
            "timeout": 600000,
            "user": {
                "displayName": "Yubico demo user",
                "id": {
                    "$base64": "3fAy6Clt4qL\/DMW23yIOG55oLxqwXvgHPKCkAeUstP0="
                },
                "name": "Yubico demo user"
            }
        },
        "requestId": "4e526585-2727-4a45-bc89-7ce0e9e2ad8c",
        "username": "Yubico demo user"
    },
    "status": "success"
}
*/

// Save requestId for registration step 2
$requestId = $registrationInitResponse['data']['requestId'];

// Extract challenge from response
$registrationInitResponse = $registrationInitResponse['data']['publicKey'];

// Fix all $base64 fields
$registrationInitResponse['challenge'] = $registrationInitResponse['challenge']['$base64'];
$registrationInitResponse['user']['id'] = $registrationInitResponse['user']['id']['$base64'];

// Fix attestation, because we support only "none"
$registrationInitResponse['attestation'] = 'none';

// Generate attestation (response to challenge)
$attestation = $authenticator->getAttestation($registrationInitResponse);

/* Example attestation:

{
    "id": "3YGXVngtu2VrTsncbWYWbuqHNBHa-apF_NloxvfodhY",
    "rawId": "3YGXVngtu2VrTsncbWYWbuqHNBHa+apF\/NloxvfodhY=",
    "response": {
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiaHliK0VZam9nQWRzRHlrMzZ3YUhPNC9zRUVleGp4TXVidnZJVGM2eHRhRT0iLCJvcmlnaW4iOiJodHRwczovL2RlbW8ueXViaWNvLmNvbSJ9",
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikxGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7dBAAAAAAAAAAAAAAAAAAAAAAAAAAAAIN2Bl1Z4Lbtla07J3G1mFm7qhzQR2vmqRfzZaMb36HYWpQECAyYgASFYIAdxNDVyO4joVSuxks08ZT6e9Fe1g6bhfdIG3XKxIDqFIlggjS0\/ahCPecxVz6YEqZ3yodDXb48ZPezlIcmoVl+2Vjg="
    },
    "type": "public-key"
}

*/


// Registration step 2 (send attestation to server)
$registrationFinishUrl = 'https://demo.yubico.com/api/v1/simple/webauthn/register-finish';
$registrationFinishRequest = [
    'requestId' => $requestId,
    'username' => 'Yubico demo user',
    'displayName' => 'Yubico demo user',
    'attestation' => [
        'attestationObject' => [
            '$base64' => $attestation['response']['attestationObject'],
        ],
        'clientDataJSON' => [
            '$base64' => $attestation['response']['clientDataJSON'],
        ]
    ],
];
$registrationFinishResponse = $httpClient
    ->post($registrationFinishUrl, ['json' => $registrationFinishRequest])
    ->getBody()
    ->getContents();
$registrationFinishResponse = json_decode($registrationFinishResponse, true);

/* Example response:
{
    "data": {
        "attestationObject": {
            "attStmt": {},
            "authData": {
                "credentialData": {
                    "aaguid": {
                        "$base64": "AAAAAAAAAAAAAAAAAAAAAA=="
                    },
                    "credentialId": {
                        "$base64": "3YGXVngtu2VrTsncbWYWbuqHNBHa+apF\/NloxvfodhY="
                    },
                    "publicKey": {
                        "-1": 1,
                        "-2": {
                            "$base64": "B3E0NXI7iOhVK7GSzTxlPp70V7WDpuF90gbdcrEgOoU="
                        },
                        "-3": {
                            "$base64": "jS0\/ahCPecxVz6YEqZ3yodDXb48ZPezlIcmoVl+2Vjg="
                        },
                        "1": 2,
                        "3": -7
                    }
                },
                "flags": {
                    "AT": true,
                    "ED": false,
                    "UP": true,
                    "UV": false,
                    "value": 65
                },
                "rpIdHash": {
                    "$base64": "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7c="
                },
                "signatureCounter": 0
            },
            "fmt": "none"
        },
        "clientData": {
            "$base64": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiaHliK0VZam9nQWRzRHlrMzZ3YUhPNC9zRUVleGp4TXVidnZJVGM2eHRhRT0iLCJvcmlnaW4iOiJodHRwczovL2RlbW8ueXViaWNvLmNvbSJ9"
        },
        "device": {
            "name": "Unknown device",
            "type": "unknown"
        },
        "parsed_x5c": null,
        "pem": null
    },
    "status": "success"
}

 */

if ($registrationFinishResponse['status'] === 'success') {
    echo "Demo user registered successfully\n";
}
