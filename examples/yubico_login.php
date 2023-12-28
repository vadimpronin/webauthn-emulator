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

$httpClient = new Client([
    'cookies' => new FileCookieJar('./cookies.json', true),
]);

// Login step 1 (request challenge from server)
$authenticationInitUrl = 'https://demo.yubico.com/api/v1/simple/webauthn/authenticate-begin';
$authenticationInitRequest = new stdClass();
$authenticationInitResponse = $httpClient
    ->post($authenticationInitUrl, ['json' => $authenticationInitRequest])
    ->getBody()
    ->getContents();
echo "\n\nauthenticationInitResponse\n" . json_encode(json_decode($authenticationInitResponse), JSON_PRETTY_PRINT) . "\n\n";
$authenticationInitResponse = json_decode($authenticationInitResponse, true);

/* Example response from Yubico demo server:
{
    "data": {
        "publicKey": {
            "allowCredentials": [
                {
                    "id": {
                        "$base64": "7XmgI6qm08kAS3jbcQNDCCo6Y3Vu65VrfHCLXxQq++k="
                    },
                    "type": "public-key"
                }
            ],
            "challenge": {
                "$base64": "6cxgmdGxM1bXiFsAQ8uperJMjEn\/36UOKIMgXcCfeRI="
            },
            "rpId": "demo.yubico.com",
            "timeout": 600000,
            "userVerification": "discouraged"
        },
        "requestId": "1128057f-c63c-4e07-bbbc-d596206ab3b3",
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
echo "\n\nassertion\n" . json_encode($assertion, JSON_PRETTY_PRINT) . "\n\n";

/* Example assertion:
{
    "id": "7XmgI6qm08kAS3jbcQNDCCo6Y3Vu65VrfHCLXxQq--k",
    "rawId": "7XmgI6qm08kAS3jbcQNDCCo6Y3Vu65VrfHCLXxQq++k=",
    "response": {
        "authenticatorData": "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7cBAAAAAA==",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiNmN4Z21kR3hNMWJYaUZzQVE4dXBlckpNakVuLzM2VU9LSU1nWGNDZmVSST0iLCJvcmlnaW4iOiJodHRwczovL2RlbW8ueXViaWNvLmNvbSJ9",
        "signature": "MEQCIDPT12ZhEDZMsrNbafpW+S+pmJSDntUYAyDbphkPp6OEAiBGGsuy7vh6eY2G1+ZoJo1s\/nN7wT435b9cAuk7Ptt5Uw==",
        "userHandle": "1EIEsZR1HYIMg+RrtSlJX453H4jhgPyyt8nPxMeOZEk="
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
echo "\n\nloginFinishResponse\n" . json_encode(json_decode($loginFinishResponse), JSON_PRETTY_PRINT) . "\n\n";
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
                        "$base64": "7XmgI6qm08kAS3jbcQNDCCo6Y3Vu65VrfHCLXxQq++k="
                    },
                    "publicKey": {
                        "-1": 1,
                        "-2": {
                            "$base64": "wbh8sO70ivmwn93rReZuyr\/N8t7Pns4IP8yE7XAzhoA="
                        },
                        "-3": {
                            "$base64": "OuqFMoMYBoO4SqcQhgux1owd5S8LfxlEnfQMNeCuUKo="
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
                "signatureCounter": 0
            },
            "clientData": {
                "challenge": "6cxgmdGxM1bXiFsAQ8uperJMjEn\/36UOKIMgXcCfeRI=",
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
