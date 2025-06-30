<?php

namespace WebauthnEmulator\Tests\Feature;

use GuzzleHttp\Client;
use GuzzleHttp\Cookie\FileCookieJar;
use GuzzleHttp\Exception\GuzzleException;
use JsonException;
use PHPUnit\Framework\TestCase;
use stdClass;
use WebauthnEmulator\Authenticator;
use WebauthnEmulator\CredentialRepository\FileRepository;

/**
 * @group E2E
 * This test performs a full registration and login flow against the live demo.quado.io server.
 * It requires an internet connection and may break if demo.quado.io changes its API.
 */
class QuadoioFlowTest extends TestCase
{
    private Authenticator $authenticator;
    private Client $httpClient;
    private string $username;
    private string $uid;
    private static Authenticator $staticAuthenticator;
    private static Client $staticHttpClient;
    private static string $staticUsername;
    private static string $staticUid;
    private static string $storagePath;
    private static string $cookiePath;

    public static function setUpBeforeClass(): void
    {
        self::$storagePath = sys_get_temp_dir() . '/quadoio_e2e_storage.txt';
        self::$cookiePath = sys_get_temp_dir() . '/quadoio_e2e_cookies.json';

        // Clean up before test suite
        if (file_exists(self::$storagePath)) {
            unlink(self::$storagePath);
        }
        if (file_exists(self::$cookiePath)) {
            unlink(self::$cookiePath);
        }

        $storage = new FileRepository(self::$storagePath);
        self::$staticAuthenticator = new Authenticator($storage);

        // Fetch API key from Quado's config JS
        $configJs = file_get_contents('https://demo.quado.io/js/config.js');
        if (!$configJs || !preg_match("(\['demo.quado.io'[^]]*])", $configJs, $matches)) {
            self::markTestSkipped('Could not retrieve API key from demo.quado.io config.');
        }
        $config = json_decode(str_replace("'", '"', $matches[0]));
        $apiKey = $config[12];

        self::$staticHttpClient = new Client([
            'cookies' => new FileCookieJar(self::$cookiePath, true),
            'timeout' => 10,
            'headers' => [
                'X-Api-Key' => $apiKey,
                'X-Quado-Ext' => 'demo',
            ],
        ]);

        $hostPartialHash = strtolower(substr(md5('quado' . gethostname()), 0, 8));
        self::$staticUsername = 'test_' . $hostPartialHash;
        self::$staticUid = $hostPartialHash . '-8801-81f2-8ae6-d1a3ce75e599';
    }

    protected function setUp(): void
    {
        // Instance properties reference static ones
        $this->authenticator = self::$staticAuthenticator;
        $this->httpClient = self::$staticHttpClient;
        $this->username = self::$staticUsername;
        $this->uid = self::$staticUid;
    }

    protected function tearDown(): void
    {
        // Don't clean up after each test - keep storage and cookies for dependent tests
    }

    public static function tearDownAfterClass(): void
    {
        // Clean up after all tests in this class are done
        if (file_exists(self::$storagePath)) {
            unlink(self::$storagePath);
        }
        if (file_exists(self::$cookiePath)) {
            unlink(self::$cookiePath);
        }
    }

    /**
     * @throws GuzzleException
     * @throws JsonException
     */
    public function testRegistrationFlow()
    {
        // Step 1: Request registration challenge
        $regInitUrl = 'https://api.quado.io/webauthn/api/v1/registrations';
        $regInitRequest = [
            'uid' => $this->uid,
            'params' => [
                'user' => [
                    'name' => $this->username,
                    'displayName' => $this->username,
                ],
                'authenticatorSelection' => [
                    'userVerification' => 'discouraged',
                ],
                'timeout' => 30000,
                'attestation' => 'none',
                'extensions' => new stdClass(),
            ],
        ];

        $regInitResponse = $this->httpClient->post($regInitUrl, ['json' => $regInitRequest]);
        $this->assertSame(201, $regInitResponse->getStatusCode());

        $regInitData = json_decode($regInitResponse->getBody()->getContents(), true);
        $this->assertArrayHasKey('fido_request', $regInitData);

        // Step 2: Generate attestation with emulator
        $attestation = $this->authenticator->getAttestation(
            registerOptions: $regInitData['fido_request'],
            origin: 'https://demo.quado.io',
            extra: ['crossOrigin' => false]
        );
        $this->assertIsArray($attestation);

        // Step 3: Send attestation to server for verification
        $regFinishUrl = 'https://api.quado.io/webauthn/api/v1/registrations';
        $regFinishRequest = [
            'fido_response' => Authenticator::base64Normal2Url($attestation),
        ];

        $regFinishResponse = $this->httpClient->patch($regFinishUrl, ['json' => $regFinishRequest]);
        $this->assertSame(201, $regFinishResponse->getStatusCode());

        $regFinishData = json_decode($regFinishResponse->getBody()->getContents(), true);
        $this->assertEquals($this->uid, $regFinishData['uid']);
    }

    /**
     * @depends testRegistrationFlow
     * @throws GuzzleException
     * @throws JsonException
     */
    public function testAuthenticationFlow()
    {
        // Step 1: Request authentication challenge
        $authInitUrl = 'https://api.quado.io/webauthn/api/v1/authentications';
        $authInitRequest = [
            'uid' => $this->uid,
            'params' => [
                'user_verification' => 'preferred',
                'timeout' => 100000,
                'extensions' => null,
            ],
        ];

        $authInitResponse = $this->httpClient->post($authInitUrl, ['json' => $authInitRequest]);
        $this->assertSame(201, $authInitResponse->getStatusCode());

        $authInitData = json_decode($authInitResponse->getBody()->getContents(), true);
        $this->assertArrayHasKey('fido_request', $authInitData);

        // Step 2: Generate assertion with emulator
        $assertion = $this->authenticator->getAssertion(
            rpId: $authInitData['fido_request']['rpId'],
            credentialIds: $authInitData['fido_request']['allowCredentials'],
            challenge: $authInitData['fido_request']['challenge'],
            origin: 'https://demo.quado.io',
            extra: ['crossOrigin' => false]
        );
        $this->assertIsArray($assertion);

        // Step 3: Send assertion to server for verification
        $authFinishUrl = 'https://api.quado.io/webauthn/api/v1/authentications';
        $authFinishRequest = [
            'fido_response' => Authenticator::base64Normal2Url($assertion),
        ];

        $authFinishResponse = $this->httpClient->patch($authFinishUrl, ['json' => $authFinishRequest]);
        $this->assertSame(201, $authFinishResponse->getStatusCode());

        $authFinishData = json_decode($authFinishResponse->getBody()->getContents(), true);
        $this->assertEquals($this->uid, $authFinishData['uid']);
    }
}
