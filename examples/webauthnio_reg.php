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
$username = 'test_' . substr(md5('webauthn' . gethostname()), 0, 8);
echo "Username: $username\n";

// Registration step 1 (request challenge from server)
$registrationInitUrl = 'https://webauthn.io/registration/options';
$registrationInitRequest = [
    'username' => $username,
    'algorithms' => ['es256'],
    'attachment' => 'all',
    'attestation' => 'none',
    'discoverable_credential' => 'preferred',
    'user_verification' => 'preferred',
];
$registrationInitResponse = $httpClient
    ->post($registrationInitUrl, ['json' => $registrationInitRequest])
    ->getBody()
    ->getContents();
echo "\n\nregistrationInitResponse\n" . json_encode(json_decode($registrationInitResponse), JSON_PRETTY_PRINT) . "\n\n";
$registrationInitResponse = json_decode($registrationInitResponse, true);

/* Example response from webauthn.io:
{
    "rp": {
        "name": "webauthn.io",
        "id": "webauthn.io"
    },
    "user": {
        "id": "dGVzdF85YjMyYzczNw",
        "name": "test_9b32c737",
        "displayName": "test_9b32c737"
    },
    "challenge": "Y5XHes9butGYo55YUQTZtFdb3J0TwM0ixzQD5tukQ1xYGdswT9Mx_06y3qLPBAYTWi_sZi9kZtMIei_hBJvMLA",
    "pubKeyCredParams": [
        {
            "type": "public-key",
            "alg": -7
        }
    ],
    "timeout": 60000,
    "excludeCredentials": [],
    "authenticatorSelection": {
        "residentKey": "preferred",
        "requireResidentKey": false,
        "userVerification": "preferred"
    },
    "attestation": "none",
    "extensions": {
        "credProps": true
    }
}
*/

// Generate attestation (response to challenge)
$attestation = $authenticator->getAttestation($registrationInitResponse);
echo "\n\nattestation\n" . json_encode($attestation, JSON_PRETTY_PRINT) . "\n\n";

/* Example attestation:

{
    "id": "PcO8YK7CUA_ywY2WJt1MFmJl1YgkLZwyjb105BeA_YU",
    "rawId": "PcO8YK7CUA\/ywY2WJt1MFmJl1YgkLZwyjb105BeA\/YU=",
    "response": {
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWTVYSGVzOWJ1dEdZbzU1WVVRVFp0RmRiM0owVHdNMGl4elFENXR1a1ExeFlHZHN3VDlNeF8wNnkzcUxQQkFZVFdpX3NaaTlrWnRNSWVpX2hCSnZNTEEiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIn0=",
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAID3DvGCuwlAP8sGNlibdTBZiZdWIJC2cMo29dOQXgP2FpQECAyYgASFYIFXuTEoAnvcGVxgkADz3j079LxRS5mKlPGYLOasCgK40IlgghgzogDfvWypLby1nJEnCNCTsYb12cXHHeWcvfUe7nAs="
    },
    "type": "public-key"
}

*/


// Registration step 2 (send attestation to server)
$registrationFinishUrl = 'https://webauthn.io/registration/verification';
$registrationFinishRequest = [
    'username' => $username,
    'response' => $attestation,
];
$registrationFinishResponse = $httpClient
    ->post($registrationFinishUrl, ['json' => $registrationFinishRequest])
    ->getBody()
    ->getContents();
echo "\n\nregistrationFinishResponse\n" . json_encode(json_decode($registrationFinishResponse), JSON_PRETTY_PRINT) . "\n\n";
$registrationFinishResponse = json_decode($registrationFinishResponse, true);

/* Example response:
{
    "verified": true
}
 */

if ($registrationFinishResponse['verified'] === true) {
    echo "User $username registered successfully\n";
}
