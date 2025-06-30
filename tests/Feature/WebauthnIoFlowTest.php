<?php

namespace WebauthnEmulator\Tests\Feature;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\ServerException;
use JsonException;
use PHPUnit\Framework\TestCase;
use WebauthnEmulator\Authenticator;
use WebauthnEmulator\CredentialRepository\InMemoryRepository;

/**
 * @group E2E
 * This test performs a full registration and login flow against the live webauthn.io demo server.
 * It requires an internet connection and may break if webauthn.io changes its API.
 */
class WebauthnIoFlowTest extends TestCase
{
    private Authenticator $authenticator;
    private Client $httpClient;
    private string $username;
    private static Authenticator $staticAuthenticator;
    private static Client $staticHttpClient;
    private static string $staticUsername;

    /**
     * @throws Exception
     */
    public static function setUpBeforeClass(): void
    {
        $storage = new InMemoryRepository();
        self::$staticAuthenticator = new Authenticator($storage);

        self::$staticHttpClient = new Client([
            'cookies' => new CookieJar(),
            'timeout' => 10,
        ]);

        self::$staticUsername = 'test_' . bin2hex(random_bytes(4));
    }

    protected function setUp(): void
    {
        // Instance properties reference static ones
        $this->authenticator = self::$staticAuthenticator;
        $this->httpClient = self::$staticHttpClient;
        $this->username = self::$staticUsername;
    }

    /**
     * @throws GuzzleException
     * @throws JsonException
     */
    public function testRegistrationFlow()
    {
        // Step 1: Request registration challenge
        $regInitResponse = $this->httpClient->post('https://webauthn.io/registration/options', [
            'json' => [
                'username' => $this->username,
                'algorithms' => ['es256'],
                'attachment' => 'all',
                'attestation' => 'none',
                'discoverable_credential' => 'preferred',
                'user_verification' => 'preferred'
            ]
        ]);
        $this->assertSame(200, $regInitResponse->getStatusCode());
        $regInitData = json_decode($regInitResponse->getBody()->getContents(), true);
        $this->assertArrayHasKey('challenge', $regInitData);

        // Step 2: Generate attestation with emulator
        $attestation = $this->authenticator->getAttestation($regInitData);
        $this->assertIsArray($attestation);

        // Step 3: Send attestation to server for verification
        $regFinishResponse = $this->httpClient->post('https://webauthn.io/registration/verification', [
            'json' => ['username' => $this->username, 'response' => $attestation]
        ]);
        $this->assertSame(200, $regFinishResponse->getStatusCode());
        $regFinishData = json_decode($regFinishResponse->getBody()->getContents(), true);

        $this->assertTrue($regFinishData['verified']);
    }

    /**
     * @depends testRegistrationFlow
     * @throws GuzzleException
     * @throws JsonException
     */
    public function testAuthenticationFlow()
    {
        // Step 0: Get session cookie (required by webauthn.io)
        $this->httpClient->get('https://webauthn.io');
        
        // Step 1: Request authentication challenge
        try {
            $authInitResponse = $this->httpClient->post('https://webauthn.io/authentication/options', [
                'json' => [
                    'username' => $this->username,
                    'user_verification' => 'preferred'
                ]
            ]);
        } catch (ServerException $e) {
            if ($e->getResponse()->getStatusCode() === 500) {
                $this->markTestSkipped('webauthn.io server error during authentication - external service issue');
            }
            throw $e;
        }
        $this->assertSame(200, $authInitResponse->getStatusCode());
        $authInitData = json_decode($authInitResponse->getBody()->getContents(), true);
        $this->assertArrayHasKey('challenge', $authInitData);

        // Step 2: Generate assertion with emulator
        $assertion = $this->authenticator->getAssertion(
            $authInitData['rpId'],
            $authInitData['allowCredentials'],
            $authInitData['challenge']
        );
        $this->assertIsArray($assertion);

        // Step 3: Send assertion to server for verification
        $authFinishResponse = $this->httpClient->post('https://webauthn.io/authentication/verification', [
            'json' => ['username' => $this->username, 'response' => $assertion]
        ]);
        $this->assertSame(200, $authFinishResponse->getStatusCode());
        $authFinishData = json_decode($authFinishResponse->getBody()->getContents(), true);

        $this->assertTrue($authFinishData['verified']);
    }
}
