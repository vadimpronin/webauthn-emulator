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

// Login step 1 (request challenge from server)
$authenticationInitUrl = 'https://api.quado.io/webauthn/api/v1/authentications';
$authenticationInitRequest = [
    'uid' => $uid,
    'params' => [
        'user_verification' => 'preferred',
        'timeout' => 100000,
        'extensions' => null,
    ],
];
$authenticationInitResponse = $httpClient
    ->post($authenticationInitUrl, ['json' => $authenticationInitRequest])
    ->getBody()
    ->getContents();
echo "\n\nauthenticationInitResponse\n" . json_encode(json_decode($authenticationInitResponse), JSON_PRETTY_PRINT) . "\n\n";
$authenticationInitResponse = json_decode($authenticationInitResponse, true);

/* Example response:
{
    "fido_request": {
        "challenge": "gIwL_eQ6DH0PlWvvZv-e5s8LnakEmKvHbJH4ItXkMYI",
        "timeout": 100000,
        "rpId": "quado.io",
        "allowCredentials": [
            {
                "id": "HB_PkyggPmHCHbcYyQCfLXTakdmq3WGCcOBjLQK3WkA",
                "type": "public-key"
            },
            {
                "id": "32fwEXE9Ri4kWPcGOVrMX4KuM0lTNuCuN7RkxrHTXhA",
                "type": "public-key"
            }
        ]
    },
    "transaction_id": "7d40a3ce-7d90-4b83-bfd4-7a8b316295ef"
}
*/


// Generate assertion
$assertion = $authenticator->getAssertion(
    rpId: $authenticationInitResponse['fido_request']['rpId'],
    credentialIds: $authenticationInitResponse['fido_request']['allowCredentials'],
    challenge: $authenticationInitResponse['fido_request']['challenge'],
    origin: 'https://demo.quado.io',
    extra: [
        'crossOrigin' => false
    ]
);
echo "\n\nassertion\n" . json_encode($assertion, JSON_PRETTY_PRINT) . "\n\n";

/* Example assertion:
{
    "id": "HB_PkyggPmHCHbcYyQCfLXTakdmq3WGCcOBjLQK3WkA",
    "rawId": "HB\/PkyggPmHCHbcYyQCfLXTakdmq3WGCcOBjLQK3WkA=",
    "response": {
        "authenticatorData": "E4Mf1Uogz5Gwtvu4tANTrL1cSUjdn5CvDL8Kk18IGJMBAAAAAA==",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiZ0l3TF9lUTZESDBQbFd2dlp2LWU1czhMbmFrRW1LdkhiSkg0SXRYa01ZSSIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby5xdWFkby5pbyJ9",
        "signature": "MEYCIQDKLFgJlBBDUhyaW30NF4nn6Ri3hAlGowzz7w+JRXVgmgIhANUiAjijkzvxkYqL06Wj1HUcuwQqwAXoZOmu\/rslzwEj",
        "userHandle": "ZmRmMWZiMjUtNjRiYy00OWRjLThjZGYtNGQxMjdjM2JmZDk2"
    },
    "type": "public-key"
}
*/


// Login step 2 (send attestation to server)
$loginFinishUrl = 'https://api.quado.io/webauthn/api/v1/authentications';

// {"fido_response":{"rawId":"70oe69_xNFx16Lw-Uq40Si2kaD-p0LYcoK-fCrxP-tY","response":{"authenticatorData":"E4Mf1Uogz5Gwtvu4tANTrL1cSUjdn5CvDL8Kk18IGJMBAAAAAA","signature":"MEQCIA-spRgvPfF_m0E-F41K0Gkfi7ZoxqJhROKAb5glxN-YAiA4kChZLKpGhlrwJuT9K_iLRARzOe1yIyB1lEfJ2ahpcw","userHandle":"OTJkZTc3NTMtMDZkNy00ZTIyLWJkYzAtNDk3MTAzMjIwNmFj","clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiUE5UcjFoZ2QxVmh3b2RfV1JsZldlb25DWDdZek02dF9EZ292My1PNEYzdyIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby5xdWFkby5pbyIsImNyb3NzT3JpZ2luIjpmYWxzZX0"},"authenticatorAttachment":"platform","getClientExtensionResults":{},"id":"70oe69_xNFx16Lw-Uq40Si2kaD-p0LYcoK-fCrxP-tY","type":"public-key"}}
$loginFinishRequest = [
    'fido_response' => $assertion,
];

// urlsafe base64
$loginFinishRequest['fido_response']['rawId'] = str_replace(['+', '/', '='], ['-', '_', ''], $loginFinishRequest['fido_response']['rawId']);
$loginFinishRequest['fido_response']['response']['authenticatorData'] = str_replace(['+', '/', '='], ['-', '_', ''], $loginFinishRequest['fido_response']['response']['authenticatorData']);
$loginFinishRequest['fido_response']['response']['clientDataJSON'] = str_replace(['+', '/', '='], ['-', '_', ''], $loginFinishRequest['fido_response']['response']['clientDataJSON']);
$loginFinishRequest['fido_response']['response']['signature'] = str_replace(['+', '/', '='], ['-', '_', ''], $loginFinishRequest['fido_response']['response']['signature']);
$loginFinishRequest['fido_response']['response']['userHandle'] = str_replace(['+', '/', '='], ['-', '_', ''], $loginFinishRequest['fido_response']['response']['userHandle']);

$loginFinishResponse = $httpClient
    ->patch($loginFinishUrl, ['json' => $loginFinishRequest])
    ->getBody()
    ->getContents();
echo "\n\nloginFinishResponse\n" . json_encode(json_decode($loginFinishResponse), JSON_PRETTY_PRINT) . "\n\n";
$loginFinishResponse = json_decode($loginFinishResponse, true);

/* Example response:
{
    "uid": "9b32c737-8801-81f2-8ae6-d1a3ce75e599",
    "transaction_id": "3c9ec597-fe3e-4773-8d4b-18e1201c4c80",
    "key_info": {
        "id": "849fec7e-83cc-4668-9aa6-4680e95bdfda",
        "user_id": "",
        "counter": 0,
        "aaguid": "00000000-0000-0000-0000-000000000000",
        "credential_id": "HB_PkyggPmHCHbcYyQCfLXTakdmq3WGCcOBjLQK3WkA",
        "attestation_type": "None",
        "attestation_format": "none",
        "created_at": "2023-12-28T12:33:20.929952Z",
        "updated_at": "2023-12-28T12:40:48.241313062Z"
    },
    "client_info": {
        "type": "webauthn.get",
        "challenge": "gIwL_eQ6DH0PlWvvZv-e5s8LnakEmKvHbJH4ItXkMYI",
        "origin": "https:\/\/demo.quado.io",
        "tokenBinding": null
    },
    "authr_info": {
        "counter": 0,
        "credential": null,
        "extensions": null,
        "flags": {
            "AT": false,
            "ED": false,
            "RFU1": false,
            "RFU21": false,
            "RFU22": false,
            "RFU23": false,
            "UP": true,
            "UV": true
        },
        "rpHash": "E4Mf1Uogz5Gwtvu4tANTrL1cSUjdn5CvDL8Kk18IGJM"
    }
}
 */

if ($loginFinishResponse['uid'] === $uid) {
    echo "User $username logged in successfully\n";
}
