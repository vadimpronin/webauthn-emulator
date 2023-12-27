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
echo "Login username: $username\n";

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
$authenticationInitResponse = json_decode($authenticationInitResponse, true);

/* Example response:
{
   "challenge":"RzckEwPCCFGmO-lkYs_z15YCKAsEcoW49X2DSuuCzL2b6iXjozuap5iVnWzenmfhbsTs0-mqKOwkvhbk8uDbRw",
   "timeout":60000,
   "rpId":"webauthn.io",
   "allowCredentials":[
      {
         "id":"2h0MoJD7Slojb_SecLOCfKyMDnC-mEDnFeYLTAefaz4",
         "type":"public-key",
         "transports":[

         ]
      },
      {
         "id":"ySHAlkz_D3-MTo2GZwXNRhDVdDLR23oQaSI3cGz-7Hc",
         "type":"public-key",
         "transports":[

         ]
      }
   ],
   "userVerification":"preferred"
}
*/


// Generate assertion
$assertion = $authenticator->getAssertion(
    $authenticationInitResponse['rpId'],
    $authenticationInitResponse['allowCredentials'],
    $authenticationInitResponse['challenge']
);

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

$loginFinishResponse = json_decode($loginFinishResponse, true);

/* Example response: {"verified": true} */

if ($loginFinishResponse['verified'] === true) {
    echo"User $username registered successfully\n";
}
