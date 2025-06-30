<?php

namespace WebauthnEmulator\Tests\Feature;

use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Exception\GuzzleException;
use JsonException;
use PHPUnit\Framework\TestCase;
use WebauthnEmulator\Authenticator;
use WebauthnEmulator\CredentialRepository\InMemoryRepository;

/**
 * @group E2E
 * This test performs a full registration and login flow against the live webauthn.lubu.ch demo server.
 * It requires an internet connection and may break if webauthn.lubu.ch changes its API.
 */
class LubuchFlowTest extends TestCase
{
    private Authenticator $authenticator;
    private Client $httpClient;
    private string $username;
    private string $uid;
    private static Authenticator $staticAuthenticator;
    private static Client $staticHttpClient;
    private static string $staticUsername;
    private static string $staticUid;

    public static function setUpBeforeClass(): void
    {
        $storage = new InMemoryRepository();
        self::$staticAuthenticator = new Authenticator($storage);

        self::$staticHttpClient = new Client([
            'cookies' => new CookieJar(),
            'timeout' => 10,
        ]);

        $hostPartialHash = strtolower(substr(md5('lubuch' . gethostname()), 0, 8));
        self::$staticUsername = 'test_' . $hostPartialHash;
        self::$staticUid = $hostPartialHash;
    }

    protected function setUp(): void
    {
        // Instance properties reference static ones
        $this->authenticator = self::$staticAuthenticator;
        $this->httpClient = self::$staticHttpClient;
        $this->username = self::$staticUsername;
        $this->uid = self::$staticUid;
    }

    /**
     * @throws GuzzleException
     * @throws JsonException
     */
    public function testRegistrationFlow()
    {
        // Step 1: Request registration challenge
        $regInitUrl = 'https://webauthn.lubu.ch/_test/server.php?fn=getCreateArgs&apple=0&yubico=0&solo=0&hypersecu=0&google=0&microsoft=0&mds=0&requireResidentKey=0&type_usb=1&type_nfc=1&type_ble=1&type_int=1&type_hybrid=1&fmt_android-key=0&fmt_android-safetynet=0&fmt_apple=0&fmt_fido-u2f=0&fmt_none=1&fmt_packed=0&fmt_tpm=0';
        $regInitRequest = [
            'rpId' => 'webauthn.lubu.ch',
            'userId' => $this->uid,
            'userName' => $this->username,
            'userDisplayName' => $this->username,
            'userVerification' => 'discouraged',
        ];
        
        $regInitResponse = $this->httpClient->get($regInitUrl . '&' . http_build_query($regInitRequest));
        $this->assertSame(200, $regInitResponse->getStatusCode());
        
        $regInitData = json_decode($regInitResponse->getBody()->getContents(), true);
        $this->assertArrayHasKey('publicKey', $regInitData);
        
        // Fix binary strings from Lubuch's response
        $regInitDataJson = json_encode($regInitData, JSON_PRETTY_PRINT);
        $regInitDataJson = str_replace(['"=?BINARY?B?', '?="'], '"', $regInitDataJson);
        $regInitData = json_decode($regInitDataJson, true);

        // Step 2: Generate attestation with emulator
        $attestation = $this->authenticator->getAttestation($regInitData['publicKey']);
        $this->assertIsArray($attestation);

        // Step 3: Send attestation to server for verification
        $regFinishUrl = 'https://webauthn.lubu.ch/_test/server.php?fn=processCreate&apple=0&yubico=0&solo=0&hypersecu=0&google=0&microsoft=0&mds=0&requireResidentKey=0&type_usb=1&type_nfc=1&type_ble=1&type_int=1&type_hybrid=1&fmt_android-key=0&fmt_android-safetynet=0&fmt_apple=0&fmt_fido-u2f=0&fmt_none=1&fmt_packed=0&fmt_tpm=0';
        $regFinishRequest = [
            'rpId' => 'webauthn.lubu.ch',
            'userId' => $this->uid,
            'userName' => $this->username,
            'userDisplayName' => $this->username,
            'userVerification' => 'discouraged',
        ];
        
        $regFinishResponse = $this->httpClient->post(
            $regFinishUrl . '&' . http_build_query($regFinishRequest),
            ['json' => $attestation['response']]
        );
        $this->assertSame(200, $regFinishResponse->getStatusCode());
        
        $regFinishData = json_decode($regFinishResponse->getBody()->getContents(), true);
        $this->assertTrue($regFinishData['success']);
        $this->assertSame('registration success.', $regFinishData['msg']);
    }

    /**
     * @depends testRegistrationFlow
     * @throws GuzzleException
     * @throws JsonException
     */
    public function testAuthenticationFlow()
    {
        // Step 0: Get session cookie (following pattern from example)
        $this->httpClient->get('https://webauthn.io');
        
        // Step 1: Request authentication challenge
        $authInitUrl = 'https://webauthn.lubu.ch/_test/server.php?fn=getGetArgs&apple=0&yubico=0&solo=0&hypersecu=0&google=0&microsoft=0&mds=0&requireResidentKey=0&type_usb=1&type_nfc=1&type_ble=1&type_int=1&type_hybrid=1&fmt_android-key=0&fmt_android-safetynet=0&fmt_apple=0&fmt_fido-u2f=0&fmt_none=1&fmt_packed=0&fmt_tpm=0';
        $authInitRequest = [
            'rpId' => 'webauthn.lubu.ch',
            'userId' => $this->uid,
            'userName' => $this->username,
            'userDisplayName' => $this->username,
            'userVerification' => 'discouraged',
        ];
        
        $authInitResponse = $this->httpClient->post($authInitUrl . '&' . http_build_query($authInitRequest));
        $this->assertSame(200, $authInitResponse->getStatusCode());
        
        $authInitData = json_decode($authInitResponse->getBody()->getContents(), true);
        $this->assertArrayHasKey('publicKey', $authInitData);
        
        // Fix binary strings from Lubuch's response
        $authInitDataJson = json_encode($authInitData, JSON_PRETTY_PRINT);
        $authInitDataJson = str_replace(['"=?BINARY?B?', '?="'], '"', $authInitDataJson);
        $authInitData = json_decode($authInitDataJson, true);

        // Step 2: Generate assertion with emulator
        $assertion = $this->authenticator->getAssertion(
            $authInitData['publicKey']['rpId'],
            $authInitData['publicKey']['allowCredentials'],
            $authInitData['publicKey']['challenge']
        );
        $this->assertIsArray($assertion);

        // Step 3: Send assertion to server for verification
        $authFinishUrl = 'https://webauthn.lubu.ch/_test/server.php?fn=processGet&apple=0&yubico=0&solo=0&hypersecu=0&google=0&microsoft=0&mds=0&requireResidentKey=0&type_usb=1&type_nfc=1&type_ble=1&type_int=1&type_hybrid=1&fmt_android-key=0&fmt_android-safetynet=0&fmt_apple=0&fmt_fido-u2f=0&fmt_none=1&fmt_packed=0&fmt_tpm=0';
        $authFinishRequest = [
            'rpId' => 'webauthn.lubu.ch',
            'userId' => $this->uid,
            'userName' => $this->username,
            'userDisplayName' => $this->username,
            'userVerification' => 'discouraged',
        ];
        
        // Lubuch expects the id field in the response
        $assertion['response']['id'] = $assertion['rawId'];
        
        $authFinishResponse = $this->httpClient->post(
            $authFinishUrl . '&' . http_build_query($authFinishRequest),
            ['json' => $assertion['response']]
        );
        $this->assertSame(200, $authFinishResponse->getStatusCode());
        
        $authFinishData = json_decode($authFinishResponse->getBody()->getContents(), true);
        $this->assertTrue($authFinishData['success']);
    }
}
