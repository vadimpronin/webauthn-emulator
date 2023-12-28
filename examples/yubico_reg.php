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

// Registration step 1 (request challenge from server)
$registrationInitUrl = 'https://demo.yubico.com/api/v1/simple/webauthn/register-begin';
$registrationInitRequest = new stdClass();
$registrationInitResponse = $httpClient
    ->post($registrationInitUrl, ['json' => $registrationInitRequest])
    ->getBody()
    ->getContents();
echo "\n\nregistrationInitResponse\n" . json_encode(json_decode($registrationInitResponse), JSON_PRETTY_PRINT) . "\n\n";
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
                "$base64": "2bqwwIuyA0MermB31MxYAChfQkvEZ9hn8TN60BQnqPE="
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
                    "$base64": "1EIEsZR1HYIMg+RrtSlJX453H4jhgPyyt8nPxMeOZEk="
                },
                "name": "Yubico demo user"
            }
        },
        "requestId": "d66e2f20-668b-4271-8649-a219029e3e4c",
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
echo "\n\nattestation\n" . json_encode($attestation, JSON_PRETTY_PRINT) . "\n\n";

/* Example attestation:

{
    "id": "7XmgI6qm08kAS3jbcQNDCCo6Y3Vu65VrfHCLXxQq--k",
    "rawId": "7XmgI6qm08kAS3jbcQNDCCo6Y3Vu65VrfHCLXxQq++k=",
    "response": {
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMmJxd3dJdXlBME1lcm1CMzFNeFlBQ2hmUWt2RVo5aG44VE42MEJRbnFQRT0iLCJvcmlnaW4iOiJodHRwczovL2RlbW8ueXViaWNvLmNvbSJ9",
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikxGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7dBAAAAAAAAAAAAAAAAAAAAAAAAAAAAIO15oCOqptPJAEt423EDQwgqOmN1buuVa3xwi18UKvvppQECAyYgASFYIMG4fLDu9Ir5sJ\/d60Xmbsq\/zfLez57OCD\/MhO1wM4aAIlggOuqFMoMYBoO4SqcQhgux1owd5S8LfxlEnfQMNeCuUKo="
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
echo "\n\nregistrationFinishResponse\n" . json_encode(json_decode($registrationFinishResponse), JSON_PRETTY_PRINT) . "\n\n";
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
            "$base64": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMmJxd3dJdXlBME1lcm1CMzFNeFlBQ2hmUWt2RVo5aG44VE42MEJRbnFQRT0iLCJvcmlnaW4iOiJodHRwczovL2RlbW8ueXViaWNvLmNvbSJ9"
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
