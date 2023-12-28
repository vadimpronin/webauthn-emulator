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

// Login step 0 (get session id cookie)
$httpClient->get('https://webauthn.io');

// Login step 1 (request challenge from server)
$authenticationInitUrl = 'https://webauthn.lubu.ch/_test/server.php?fn=getGetArgs&apple=0&yubico=0&solo=0&hypersecu=0&google=0&microsoft=0&mds=0&requireResidentKey=0&type_usb=1&type_nfc=1&type_ble=1&type_int=1&type_hybrid=1&fmt_android-key=0&fmt_android-safetynet=0&fmt_apple=0&fmt_fido-u2f=0&fmt_none=1&fmt_packed=0&fmt_tpm=0';
$authenticationInitRequest = [
    'rpId' => 'webauthn.lubu.ch',
    'userId' => $uid,
    'userName' => $username,
    'userDisplayName' => $username,
    'userVerification' => 'discouraged',
];
$authenticationInitResponse = $httpClient
    ->post($authenticationInitUrl . '&' . http_build_query($authenticationInitRequest))
    ->getBody()
    ->getContents();
echo "\n\nauthenticationInitResponse\n" . json_encode(json_decode($authenticationInitResponse), JSON_PRETTY_PRINT) . "\n\n";
$authenticationInitResponse = json_decode($authenticationInitResponse, true);

/* Example response:
{
    "publicKey": {
        "timeout": 240000,
        "challenge": "=?BINARY?B?0QQTqvOz4HavYF000ZvY6uVT77gGSOKQxShU7PINhqs=?=",
        "userVerification": "discouraged",
        "rpId": "webauthn.lubu.ch",
        "allowCredentials": [
            {
                "id": "=?BINARY?B?t8xQ51zTUev5o09GFFzuqWbsdd2z\/gEdAkN3jP5FI4o=?=",
                "transports": [
                    "usb",
                    "nfc",
                    "ble",
                    "hybrid",
                    "internal"
                ],
                "type": "public-key"
            },
            {
                "id": "=?BINARY?B?6yCmeBTCOSCEXFd+mCuuBbufvgA3LQT7JuElf7bXojE=?=",
                "transports": [
                    "usb",
                    "nfc",
                    "ble",
                    "hybrid",
                    "internal"
                ],
                "type": "public-key"
            }
        ]
    }
}
*/

// Small hack to fix the binary strings
$authenticationInitResponse = json_encode($authenticationInitResponse, JSON_PRETTY_PRINT);
$authenticationInitResponse = str_replace(['"=?BINARY?B?', '?="'], '"', $authenticationInitResponse);
$authenticationInitResponse = json_decode($authenticationInitResponse, true);


// Generate assertion
$assertion = $authenticator->getAssertion(
    $authenticationInitResponse['publicKey']['rpId'],
    $authenticationInitResponse['publicKey']['allowCredentials'],
    $authenticationInitResponse['publicKey']['challenge']
);
echo "\n\nassertion\n" . json_encode($assertion, JSON_PRETTY_PRINT) . "\n\n";


/* Example assertion:
{
    "id": "t8xQ51zTUev5o09GFFzuqWbsdd2z_gEdAkN3jP5FI4o",
    "rawId": "t8xQ51zTUev5o09GFFzuqWbsdd2z\/gEdAkN3jP5FI4o=",
    "response": {
        "authenticatorData": "wib1OPW9EkDeiwUoyTgJ1+PpFG4dljeXodqRX15DG+gBAAAABQ==",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiMFFRVHF2T3o0SGF2WUYwMDBadlk2dVZUNzdnR1NPS1F4U2hVN1BJTmhxcz0iLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmx1YnUuY2gifQ==",
        "signature": "MEUCIQCh16UwW\/vVZZN+8P4MqmMpT9teAS7dtLOUusrUV\/B4HAIgPsYKEwEXjVvyoqDsys+YQYW\/mJSUrYRkxSRZZ4\/wlT8=",
        "userHandle": "mzLHNw=="
    },
    "type": "public-key"
}
*/

// Login step 2 (send attestation to server)
$loginFinishUrl = 'https://webauthn.lubu.ch/_test/server.php?fn=processGet&apple=0&yubico=0&solo=0&hypersecu=0&google=0&microsoft=0&mds=0&requireResidentKey=0&type_usb=1&type_nfc=1&type_ble=1&type_int=1&type_hybrid=1&fmt_android-key=0&fmt_android-safetynet=0&fmt_apple=0&fmt_fido-u2f=0&fmt_none=1&fmt_packed=0&fmt_tpm=0';
$loginFinishRequest = [
    'rpId' => 'webauthn.lubu.ch',
    'userId' => $uid,
    'userName' => $username,
    'userDisplayName' => $username,
    'userVerification' => 'discouraged',
];
$assertion['response']['id'] = $assertion['rawId'];

$loginFinishResponse = $httpClient
    ->post($loginFinishUrl . '&' . http_build_query($loginFinishRequest), ['json' => $assertion['response']])
    ->getBody()
    ->getContents();
echo "\n\nloginFinishResponse\n" . json_encode(json_decode($loginFinishResponse), JSON_PRETTY_PRINT) . "\n\n";
$loginFinishResponse = json_decode($loginFinishResponse, true);

/* Example response:
{
    "success": true
}
 */

if ($loginFinishResponse['success'] === true) {
    echo"User $username logged in successfully\n";
}
