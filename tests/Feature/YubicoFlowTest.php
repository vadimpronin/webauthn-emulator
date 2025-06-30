<?php

namespace WebauthnEmulator\Tests\Feature;

use GuzzleHttp\Client;
use GuzzleHttp\Cookie\FileCookieJar;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\ServerException;
use JsonException;
use PHPUnit\Framework\TestCase;
use stdClass;
use WebauthnEmulator\Authenticator;
use WebauthnEmulator\CredentialRepository\FileRepository;

/**
 * @group E2E
 * This test performs a full registration and login flow against the live demo.yubico.com server.
 * It requires an internet connection and may break if demo.yubico.com changes its API.
 */
class YubicoFlowTest extends TestCase
{
    private Authenticator $authenticator;
    private Client $httpClient;
    private string $requestId;
    private static Authenticator $staticAuthenticator;
    private static Client $staticHttpClient;
    private static string $staticRequestId;
    private static string $storagePath;
    private static string $cookiePath;

    public static function setUpBeforeClass(): void
    {
        self::$storagePath = sys_get_temp_dir() . '/yubico_e2e_storage.txt';
        self::$cookiePath = sys_get_temp_dir() . '/yubico_e2e_cookies.json';
        
        // Clean up before test suite
        if (file_exists(self::$storagePath)) unlink(self::$storagePath);
        if (file_exists(self::$cookiePath)) unlink(self::$cookiePath);

        $storage = new FileRepository(self::$storagePath);
        self::$staticAuthenticator = new Authenticator($storage);

        self::$staticHttpClient = new Client([
            'cookies' => new FileCookieJar(self::$cookiePath, true),
            'timeout' => 10,
        ]);

        self::$staticRequestId = '';
    }

    protected function setUp(): void
    {
        // Instance properties reference static ones
        $this->authenticator = self::$staticAuthenticator;
        $this->httpClient = self::$staticHttpClient;
        $this->requestId = self::$staticRequestId;
    }

    protected function tearDown(): void
    {
        // Don't clean up after each test - keep storage and cookies for dependent tests
    }
    
    public static function tearDownAfterClass(): void
    {
        // Clean up after all tests in this class are done
        if (file_exists(self::$storagePath)) unlink(self::$storagePath);
        if (file_exists(self::$cookiePath)) unlink(self::$cookiePath);
    }

    /**
     * @throws GuzzleException
     * @throws JsonException
     */
    public function testRegistrationFlow()
    {
        // Step 1: Request registration challenge
        $regInitUrl = 'https://demo.yubico.com/api/v1/simple/webauthn/register-begin';
        $regInitRequest = new stdClass(); // Yubico expects empty object
        
        $regInitResponse = $this->httpClient->post($regInitUrl, ['json' => $regInitRequest]);
        $this->assertSame(200, $regInitResponse->getStatusCode());
        
        $regInitData = json_decode($regInitResponse->getBody()->getContents(), true);
        $this->assertArrayHasKey('data', $regInitData);
        $this->assertArrayHasKey('publicKey', $regInitData['data']);
        $this->assertArrayHasKey('requestId', $regInitData['data']);
        
        // Save requestId for authentication test
        self::$staticRequestId = $this->requestId = $regInitData['data']['requestId'];
        
        // Convert Yubico's challenge format
        if (isset($regInitData['data']['publicKey']['challenge']['$base64'])) {
            $regInitData['data']['publicKey']['challenge'] = $regInitData['data']['publicKey']['challenge']['$base64'];
        }
        
        // Convert user.id format
        if (isset($regInitData['data']['publicKey']['user']['id']['$base64'])) {
            $regInitData['data']['publicKey']['user']['id'] = $regInitData['data']['publicKey']['user']['id']['$base64'];
        }
        
        // Override attestation to 'none' since our emulator doesn't support 'direct'
        $regInitData['data']['publicKey']['attestation'] = 'none';

        // Step 2: Generate attestation with emulator
        $attestation = $this->authenticator->getAttestation($regInitData['data']['publicKey']);
        $this->assertIsArray($attestation);

        // Step 3: Send attestation to server for verification
        $regFinishUrl = 'https://demo.yubico.com/api/v1/simple/webauthn/register-finish';
        $regFinishRequest = [
            'requestId' => $regInitData['data']['requestId'],
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
        
        $regFinishResponse = $this->httpClient->post($regFinishUrl, ['json' => $regFinishRequest]);
        $this->assertSame(200, $regFinishResponse->getStatusCode());
        
        $regFinishData = json_decode($regFinishResponse->getBody()->getContents(), true);
        $this->assertArrayHasKey('status', $regFinishData);
        $this->assertSame('success', $regFinishData['status']);
    }

    /**
     * @depends testRegistrationFlow
     * @throws GuzzleException
     * @throws JsonException
     */
    public function testAuthenticationFlow()
    {
        // Step 1: Request authentication challenge
        $authInitUrl = 'https://demo.yubico.com/api/v1/simple/webauthn/authenticate-begin';
        $authInitRequest = new stdClass(); // Yubico expects empty object
        
        try {
            $authInitResponse = $this->httpClient->post($authInitUrl, ['json' => $authInitRequest]);
        } catch (ServerException $e) {
            if ($e->getResponse()->getStatusCode() === 500) {
                $this->markTestSkipped('demo.yubico.com server error during authentication - external service issue');
            }
            throw $e;
        }
        
        $this->assertSame(200, $authInitResponse->getStatusCode());
        
        $authInitData = json_decode($authInitResponse->getBody()->getContents(), true);
        $this->assertArrayHasKey('data', $authInitData);
        $this->assertArrayHasKey('publicKey', $authInitData['data']);
        
        // Convert Yubico's challenge format
        if (isset($authInitData['data']['publicKey']['challenge']['$base64'])) {
            $authInitData['data']['publicKey']['challenge'] = $authInitData['data']['publicKey']['challenge']['$base64'];
        }
        
        // Convert allowCredentials id format
        if (isset($authInitData['data']['publicKey']['allowCredentials'])) {
            foreach ($authInitData['data']['publicKey']['allowCredentials'] as &$cred) {
                if (isset($cred['id']['$base64'])) {
                    $cred['id'] = $cred['id']['$base64'];
                }
            }
        }

        // Step 2: Generate assertion with emulator
        $assertion = $this->authenticator->getAssertion(
            $authInitData['data']['publicKey']['rpId'],
            $authInitData['data']['publicKey']['allowCredentials'],
            $authInitData['data']['publicKey']['challenge']
        );
        $this->assertIsArray($assertion);

        // Step 3: Send assertion to server for verification
        $authFinishUrl = 'https://demo.yubico.com/api/v1/simple/webauthn/authenticate-finish';
        $authFinishRequest = [
            'requestId' => $authInitData['data']['requestId'],
            'assertion' => [
                'credentialId' => [
                    '$base64' => $assertion['rawId']
                ],
                'authenticatorData' => [
                    '$base64' => $assertion['response']['authenticatorData']
                ],
                'clientDataJSON' => [
                    '$base64' => $assertion['response']['clientDataJSON']
                ],
                'signature' => [
                    '$base64' => $assertion['response']['signature']
                ]
            ]
        ];
        
        $authFinishResponse = $this->httpClient->post($authFinishUrl, ['json' => $authFinishRequest]);
        $this->assertSame(200, $authFinishResponse->getStatusCode());
        
        $authFinishData = json_decode($authFinishResponse->getBody()->getContents(), true);
        $this->assertArrayHasKey('status', $authFinishData);
        $this->assertSame('success', $authFinishData['status']);
    }
}