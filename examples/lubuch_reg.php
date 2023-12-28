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

// pseudo-random username based on hostname
$hostPartialHash = strtolower(substr(md5('webauthn' . gethostname()), 0, 8));
$username = 'test_' . $hostPartialHash;
$uid = $hostPartialHash;
echo "Username: $username\n";
echo "UID: $uid\n";

// Registration step 1 (request challenge from server)
$registrationInitUrl = 'https://webauthn.lubu.ch/_test/server.php?fn=getCreateArgs&apple=0&yubico=0&solo=0&hypersecu=0&google=0&microsoft=0&mds=0&requireResidentKey=0&type_usb=1&type_nfc=1&type_ble=1&type_int=1&type_hybrid=1&fmt_android-key=0&fmt_android-safetynet=0&fmt_apple=0&fmt_fido-u2f=0&fmt_none=1&fmt_packed=0&fmt_tpm=0';
$registrationInitRequest = [
    'rpId' => 'webauthn.lubu.ch',
    'userId' => $uid,
    'userName' => $username,
    'userDisplayName' => $username,
    'userVerification' => 'discouraged',
];
$registrationInitResponse = $httpClient
    ->get($registrationInitUrl . '&' . http_build_query($registrationInitRequest))
    ->getBody()
    ->getContents();
echo "\n\nregistrationInitResponse\n" . json_encode(json_decode($registrationInitResponse), JSON_PRETTY_PRINT) . "\n\n";
$registrationInitResponse = json_decode($registrationInitResponse, true);

/* Example response from webauthn.lubu.ch:
{
    "publicKey": {
        "rp": {
            "name": "WebAuthn Library",
            "id": "webauthn.lubu.ch"
        },
        "authenticatorSelection": {
            "userVerification": "discouraged"
        },
        "user": {
            "id": "=?BINARY?B?mzLHNw==?=",
            "name": "test9b32c737",
            "displayName": "test9b32c737"
        },
        "pubKeyCredParams": [
            {
                "type": "public-key",
                "alg": -8
            },
            {
                "type": "public-key",
                "alg": -7
            },
            {
                "type": "public-key",
                "alg": -257
            }
        ],
        "attestation": "none",
        "extensions": {
            "exts": true
        },
        "timeout": 240000,
        "challenge": "=?BINARY?B?gYIWNflMo8Fclb1OL0acFiRIjFo0HdnSo7l7\/BOPep0=?=",
        "excludeCredentials": []
    }
}
*/

// Small hack to fix the binary strings
$registrationInitResponse = json_encode($registrationInitResponse, JSON_PRETTY_PRINT);
$registrationInitResponse = str_replace(['"=?BINARY?B?', '?="'], '"', $registrationInitResponse);
$registrationInitResponse = json_decode($registrationInitResponse, true);

// Generate attestation (response to challenge)
$attestation = $authenticator->getAttestation($registrationInitResponse['publicKey']);
echo "\n\nattestation\n" . json_encode($attestation, JSON_PRETTY_PRINT) . "\n\n";

/* Example attestation:
{
    "id": "6yCmeBTCOSCEXFd-mCuuBbufvgA3LQT7JuElf7bXojE",
    "rawId": "6yCmeBTCOSCEXFd+mCuuBbufvgA3LQT7JuElf7bXojE=",
    "response": {
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZ1lJV05mbE1vOEZjbGIxT0wwYWNGaVJJakZvMEhkblNvN2w3L0JPUGVwMD0iLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmx1YnUuY2gifQ==",
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikwib1OPW9EkDeiwUoyTgJ1+PpFG4dljeXodqRX15DG+hBAAAAAAAAAAAAAAAAAAAAAAAAAAAAIOsgpngUwjkghFxXfpgrrgW7n74ANy0E+ybhJX+216IxpQECAyYgASFYIN5gSEQG6ePGr0nAJdn3GW+RKpEerAJeZvpOKvlr+E6uIlggq8d0YpZyG9GgWlCsIAt3xJ7O4ci6gNKV1iv8UntU+g8="
    },
    "type": "public-key"
}
*/


// Registration step 2 (send attestation to server)
$registrationFinishUrl = 'https://webauthn.lubu.ch/_test/server.php?fn=processCreate&apple=0&yubico=0&solo=0&hypersecu=0&google=0&microsoft=0&mds=0&requireResidentKey=0&type_usb=1&type_nfc=1&type_ble=1&type_int=1&type_hybrid=1&fmt_android-key=0&fmt_android-safetynet=0&fmt_apple=0&fmt_fido-u2f=0&fmt_none=1&fmt_packed=0&fmt_tpm=0';
$registrationFinishRequest = [
    'rpId' => 'webauthn.lubu.ch',
    'userId' => $uid,
    'userName' => $username,
    'userDisplayName' => $username,
    'userVerification' => 'discouraged',
];
$registrationFinishResponse = $httpClient
    ->post($registrationFinishUrl . '&' . http_build_query($registrationFinishRequest), ['json' => $attestation['response']])
    ->getBody()
    ->getContents();
echo "\n\nregistrationFinishResponse\n" . json_encode(json_decode($registrationFinishResponse), JSON_PRETTY_PRINT) . "\n\n";
$registrationFinishResponse = json_decode($registrationFinishResponse, true);

/* Example response:
{
    "success": true,
    "msg": "registration success."
}
 */

if ($registrationFinishResponse['success'] === true) {
    echo "User $username registered successfully\n";
} else {
    dump($registrationFinishResponse);
}
