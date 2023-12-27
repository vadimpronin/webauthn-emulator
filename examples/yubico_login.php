<?php

use GuzzleHttp\Client;
use GuzzleHttp\Cookie\FileCookieJar;
use WebauthnEmulator\Authenticator;
use WebauthnEmulator\CredentialRepository\FileRepository;

require_once __DIR__ . '/../vendor/autoload.php';

$storage = new FileRepository('./key_storage.json');

$httpClient = new Client([
    'cookies' => new FileCookieJar('./cookies.json', true),
]);

$authenticator = new Authenticator($storage);

// Login step 1 (request challenge from server)
$authenticationInitUrl = 'https://demo.yubico.com/api/v1/simple/webauthn/authenticate-begin';
$authenticationInitRequest = new stdClass();
$authenticationInitResponse = $httpClient
    ->post($authenticationInitUrl, ['json' => $authenticationInitRequest])
    ->getBody()
    ->getContents();
$authenticationInitResponse = json_decode($authenticationInitResponse, true);

/* Example response from Yubico demo server:
{
    "data": {
        "publicKey": {
            "allowCredentials": [
                {
                    "id": {
                        "$base64": "BZUtmf2Nq8iAhis0P\/1ys1qKeQfHPZnEldkLAIeaG2E="
                    },
                    "type": "public-key"
                }
            ],
            "challenge": {
                "$base64": "AXty\/2y9gnlLIBbzr4MMKWUEBl1AjuGhD2nuVBhW5aE="
            },
            "rpId": "demo.yubico.com",
            "timeout": 600000,
            "userVerification": "discouraged"
        },
        "requestId": "433e58d7-44d0-47e1-8907-5a24f0086167",
        "username": "Yubico demo user"
    },
    "status": "success"
}
*/

// Save requestId for later
$requestId = $authenticationInitResponse['data']['requestId'];

// Fix $base64 fields
$allowCredentials = $authenticationInitResponse['data']['publicKey']['allowCredentials'];
foreach ($allowCredentials as &$allowCredential) {
    $allowCredential['id'] = $allowCredential['id']['$base64'];
}

// Generate assertion
$assertion = $authenticator->getAssertion(
    $authenticationInitResponse['data']['publicKey']['rpId'],
    $allowCredentials,
    $authenticationInitResponse['data']['publicKey']['challenge']['$base64'],
);

/* Example assertion:

{
    "id": "BZUtmf2Nq8iAhis0P%2F1ys1qKeQfHPZnEldkLAIeaG2E%3D",
    "rawId": "BZUtmf2Nq8iAhis0P\/1ys1qKeQfHPZnEldkLAIeaG2E=",
    "response": {
        "authenticatorData": "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7cBAAAAAQ==",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQVh0eS8yeTlnbmxMSUJienI0TU1LV1VFQmwxQWp1R2hEMm51VkJoVzVhRT0iLCJvcmlnaW4iOiJodHRwczovL2RlbW8ueXViaWNvLmNvbSJ9",
        "signature": "MEUCIQCeRAXgSvAc\/\/dp+I3zi+WHxn\/7ym3BcRZIzH4VuydkhQIgY8fjRF3pd8E2\/ELxQJts\/yhT1iho21DM8Zhd2fZ9fbg=",
        "userHandle": "\/5cLEQmaS\/0cAEHxtjdP70Atbk\/7Mj9AtlD8crb3xdM="
    },
    "type": "public-key"
}

*/


// Login step 2 (send attestation to server)
$loginFinishUrl = 'https://demo.yubico.com/api/v1/simple/webauthn/authenticate-finish';
$loginFinishRequest = [
    'requestId' => $requestId,
    'assertion' => [
        'credentialId' => [
            '$base64' => $assertion['rawId']
        ],
        'authenticatorData' => [
            '$base64' => $assertion['response']['authenticatorData']
        ],
        'clientDataJSON' => [
            '$base64' => $assertion['response']['clientDataJSON']
        ],
        'signature' => [
            '$base64' => $assertion['response']['signature']
        ]
    ]
];
$loginFinishResponse = $httpClient
    ->post($loginFinishUrl, ['json' => $loginFinishRequest])
    ->getBody()
    ->getContents();

$loginFinishResponse = json_decode($loginFinishResponse, true);

/* Example response:
{
    "data": {
        "authenticatorData": {
            "authData": {
                "credentialData": {
                    "aaguid": {
                        "$base64": "AAAAAAAAAAAAAAAAAAAAAA=="
                    },
                    "credentialId": {
                        "$base64": "BZUtmf2Nq8iAhis0P\/1ys1qKeQfHPZnEldkLAIeaG2E="
                    },
                    "publicKey": {
                        "-1": 1,
                        "-2": {
                            "$base64": "9cGUinxuZ2NdjLQpdphvS6EuhLQlk84ZMkyCya+E2\/c="
                        },
                        "-3": {
                            "$base64": "hC8Tf0s8bqHr70+3X9toGhGrVek3HTtBRzufG52kGYc="
                        },
                        "1": 2,
                        "3": -7
                    }
                },
                "flags": {
                    "AT": false,
                    "ED": false,
                    "UP": true,
                    "UV": false,
                    "value": 1
                },
                "rpIdHash": {
                    "$base64": "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7c="
                },
                "signatureCounter": 1
            },
            "clientData": {
                "challenge": "AXty\/2y9gnlLIBbzr4MMKWUEBl1AjuGhD2nuVBhW5aE=",
                "origin": "https:\/\/demo.yubico.com",
                "type": "webauthn.get"
            }
        },
        "username": "Yubico demo user"
    },
    "status": "success"
}
 */

if ($loginFinishResponse['status'] === 'success') {
    echo "Demo user logged in successfully\n";
}
