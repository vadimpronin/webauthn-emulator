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

// Login step 0 (get session id cookie)
$httpClient->get('https://webauthn.io');

// Login step 1 (request challenge from server)
$authenticationInitUrl = 'https://webauthn.io/authentication/options';
$authenticationInitRequest = [
    'username' => $username,
    'user_verification' => 'preferred',
];
$authenticationInitResponse = $httpClient
    ->post($authenticationInitUrl, ['json' => $authenticationInitRequest])
    ->getBody()
    ->getContents();
echo "\n\nauthenticationInitResponse\n" . json_encode(json_decode($authenticationInitResponse), JSON_PRETTY_PRINT) . "\n\n";
$authenticationInitResponse = json_decode($authenticationInitResponse, true);

/* Example response from webauthn.io:
{
    "challenge": "C3It6TxHHOLd6qP_XN9Rt-qBsLUClus0YDuZXOSA8ewdRQRn5qm0cgpRQfR_lrz_CytOS4ryY7qRYQ2KD51M-A",
    "timeout": 60000,
    "rpId": "webauthn.io",
    "allowCredentials": [
        {
            "id": "2h0MoJD7Slojb_SecLOCfKyMDnC-mEDnFeYLTAefaz4",
            "type": "public-key",
            "transports": []
        },
        {
            "id": "AiMGnemw3W__9R7qxOE_qhm1IRjETv5hagTUAaALlC8",
            "type": "public-key",
            "transports": []
        }
    ],
    "userVerification": "preferred"
}
*/


// Generate assertion
$assertion = $authenticator->getAssertion(
    $authenticationInitResponse['rpId'],
    $authenticationInitResponse['allowCredentials'],
    $authenticationInitResponse['challenge']
);
echo "\n\nassertion\n" . json_encode($assertion, JSON_PRETTY_PRINT) . "\n\n";

/* Example assertion:
{
    "id": "AiMGnemw3W__9R7qxOE_qhm1IRjETv5hagTUAaALlC8",
    "rawId": "AiMGnemw3W\/\/9R7qxOE\/qhm1IRjETv5hagTUAaALlC8=",
    "response": {
        "authenticatorData": "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvABAAAAAQ==",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiQzNJdDZUeEhIT0xkNnFQX1hOOVJ0LXFCc0xVQ2x1czBZRHVaWE9TQThld2RSUVJuNXFtMGNncFJRZlJfbHJ6X0N5dE9TNHJ5WTdxUllRMktENTFNLUEiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIn0=",
        "signature": "MEUCIAREoVd0Fj33a1\/iudefMlXE4HyIGZJAngNdeU8oeWKEAiEAquqA99iwzIpFOq9cE8qDIRU42xR0Q9q9hdHCt2dHuHY=",
        "userHandle": "dGVzdF85YjMyYzczNw"
    },
    "type": "public-key"
}
*/


// Login step 2 (send attestation to server)
$loginFinishUrl = 'https://webauthn.io/authentication/verification';
$loginFinishRequest = [
    'username' => $username,
    'response' => $assertion,
];
$loginFinishResponse = $httpClient
    ->post($loginFinishUrl, ['json' => $loginFinishRequest])
    ->getBody()
    ->getContents();
echo "\n\nloginFinishResponse\n" . json_encode(json_decode($loginFinishResponse), JSON_PRETTY_PRINT) . "\n\n";
$loginFinishResponse = json_decode($loginFinishResponse, true);

/* Example response:
{
    "verified": true
}
 */

if ($loginFinishResponse['verified'] === true) {
    echo"User $username logged in successfully\n";
}
