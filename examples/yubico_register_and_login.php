<?php

use GuzzleHttp\Client;
use WebauthnEmulator\Authenticator;
use WebauthnEmulator\CredentialRepository\FileRepository;

require_once __DIR__ . '/../vendor/autoload.php';

$storage = new FileRepository('tmp/test_storage.json');

$httpClient = new Client([
    'cookies' => true,
]);

$authenticator = new Authenticator($storage);

$data = ["userVerification" => "discouraged"];
// start
$response = $httpClient->post('https://demo.yubico.com/api/v1/simple/webauthn/register-begin', ['json' => $data]);

$pkcco = json_decode($response->getBody()->getContents(), true)['data'];
dump('register start response: ');
dump($pkcco);
$pkcco["publicKey"]["attestation"] = 'none';

// finish register
$attestation = $authenticator->getAttestation($pkcco['publicKey']);

$data = $pkcco;
unset($data["publicKey"]);

$data["attestation"] = [
    "attestationObject" => $attestation['response']['attestationObject'],
    "clientDataJSON" => $attestation['response']['clientDataJSON'],
];

dump('register finish request:');
dump($data);
echo "\n\n\n";

$response = $httpClient->post('https://demo.yubico.com/api/v1/simple/webauthn/register-finish', ['json' => $data]);

$decodedResponse = json_decode($response->getBody()->getContents(), true, 512, JSON_THROW_ON_ERROR);

dump('register finish response:');
dump($decodedResponse);
echo "\n\n\n";

if ($decodedResponse['status'] === 'success') {
    dump('registered credential saved');
}


// -------------------- end register -------------------//


// --------------------- login ----------------- //

$data = ["userVerification" => "discouraged"];
$response = $httpClient->post('https://demo.yubico.com/api/v1/simple/webauthn/authenticate-begin', ['json' => $data]);

$pkcro = json_decode($response->getBody()->getContents(), true)['data'];

dump('publicKeyCredentialRequestOptions: ');
dump($pkcro);
echo "\n\n\n";

$rpId = $pkcro['publicKey']['rpId'];
$challenge = $pkcro['publicKey']['challenge'];

$credentialId = array_pop($pkcro['publicKey']['allowCredentials'])['id'] ?? null;
if ($credentialId === null) {
    throw new RuntimeException('credential id not found in response');
}

$assertion = $authenticator->getAssertion($rpId, $credentialId, $challenge);

dump('credential assertion: ');
dump($assertion);
echo "\n\n\n";

$data = [
    "requestId" => $pkcro["requestId"],
    "assertion" => [
        "credentialId" => $assertion['rawId'],
        "authenticatorData" => $assertion['response']['authenticatorData'],
        "clientDataJSON" => $assertion['response']['clientDataJSON'],
        "signature" => $assertion['response']['signature'],
    ],
];

dump('auth finish request');
dump($data);
echo "\n\n\n";

$response = $httpClient->post('https://demo.yubico.com/api/v1/simple/webauthn/authenticate-finish', ['json' => $data]);

dump('auth finish response:');
dump($response->getBody()->getContents());
echo "\n\n\n";

// ---------------- end login ------------------ //