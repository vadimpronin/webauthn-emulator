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

// pseudo-random username based on hostname
$username = 'test_' . substr(md5('webauthn' . gethostname()), 0, 8);
echo "Registration username: $username\n";

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
$registrationInitResponse = json_decode($registrationInitResponse, true);

/* Example response from webauthn.io:
{
   "rp":{
      "name":"webauthn.io",
      "id":"webauthn.io"
   },
   "user":{
      "id":"dGVzdDMxNA",
      "name":"test777",
      "displayName":"test777"
   },
   "challenge":"7BYLAiLMeNm3103ZBmBIHxEI-5-O_5uWtkaNWC4oTzR47KtFLfs7oy0i0qCJ3A-ENpvsNMbdWbkHGvcFZyhBZQ",
   "pubKeyCredParams":[
      {
         "type":"public-key",
         "alg":-7
      }
   ],
   "timeout":60000,
   "excludeCredentials":[

   ],
   "authenticatorSelection":{
      "residentKey":"preferred",
      "requireResidentKey":false,
      "userVerification":"preferred"
   },
   "attestation":"none",
   "extensions":{
      "credProps":true
   }
}
*/

// Generate attestation (response to challenge)
$attestation = $authenticator->getAttestation($registrationInitResponse);

/* Example attestation:

{
    "id": "sKuFSbP7ZK0NIjgKhoWrOX5sSJBLvVvhIUHPwYsuUVg",
    "rawId": "sKuFSbP7ZK0NIjgKhoWrOX5sSJBLvVvhIUHPwYsuUVg=",
    "response": {
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiN0JZTEFpTE1lTm0zMTAzWkJtQklIeEVJLTUtT181dVd0a2FOV0M0b1R6UjQ3S3RGTGZzN295MGkwcUNKM0EtRU5wdnNOTWJkV2JrSEd2Y0ZaeWhCWlEiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIn0=",
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAILCrhUmz+2StDSI4CoaFqzl+bEiQS71b4SFBz8GLLlFYpQECAyYgASFYIBOwQof249qcQXF9yVDuqwgUDd9c7cD0LMmrmgqYpuNXIlgg4gzdJgb0tesv0UcfW31NsIXM6AuGqLYJIjjgKoA8sVg="
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
$registrationFinishResponse = json_decode($registrationFinishResponse, true);

/* Example response: {"verified": true} */

if ($registrationFinishResponse['verified'] === true) {
    echo "User $username registered successfully\n";
}
