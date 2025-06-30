# WebAuthn Emulator
*A simple PHP WebAuthn (FIDO2) client library*

`webauthn-emulator` is a PHP library that emulates WebAuthn-compatible authenticators like YubiKeys, Touch ID, Face ID,
Windows Hello, etc. It essentially simulates the behavior
of [Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API) of a browser,
allowing the developers to integrate WebAuthn client-side authentication into their applications.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
    - [Initialization](#initialization)
    - [Registration (Attestation)](#registration-attestation)
    - [Authentication (Assertion)](#authentication-assertion)
    - [Base64url vs Base64 Encoding](#base64url-vs-base64-encoding)
- [More Examples](#more-examples)
- [Storing Credentials](#storing-credentials)
- [Testing](#testing)
- [Limitations](#limitations)
- [Contributing and Reporting Issues](#contributing-and-reporting-issues)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Features

- Generate responses for WebAuthn registration (attestation) and authentication (assertion) requests.
- Works with any key storage.
- Supports multiple users and credentials.

## Installation

The recommended way to install `webauthn-emulator` is through [Composer](https://getcomposer.org/):

```bash
composer require pronin/webauthn-emulator
```

## Quick Start

After installing `webauthn-emulator` via Composer, you can quickly begin by creating an instance of the `Authenticator`
class and using it to handle WebAuthn registration and authentication.

Initialize the authenticator:

```php
<?php
use WebauthnEmulator\Authenticator;
use WebauthnEmulator\CredentialRepository\FileRepository;

// Instantiate the file repository to store credentials
$storage = new FileRepository('path/to/credential/storage.txt');

// Create the authenticator instance
$authenticator = new Authenticator($storage);
```

Generate a response to a registration challenge:

```php
// Sample registration challenge. See examples/webauthnio_reg.php for a complete example.
$registrationChallenge = 
    "rp" => [
        "name" => "webauthn.io",
        "id" => "webauthn.io"
    ],
    "user" => [
        "id" => "dGVzdDMxNA",
        "name" => "test777",
        "displayName" => "test777"
    ],
    "challenge" => "7BYLAiLMeNm3103ZBmBIHxEI-5-O_5uWtkaNWC4oTzR47KtFLfs7oy0i0qCJ3A-ENpvsNMbdWbkHGvcFZyhBZQ",
    "pubKeyCredParams" => [
        [
            "type" => "public-key",
            "alg" => -7
        ]
    ],
    "timeout" => 60000,
    "excludeCredentials" => [],
    "authenticatorSelection" => [
        "residentKey" => "preferred",
        "requireResidentKey" => false,
        "userVerification" => "preferred"
    ],
    "attestation" => "none",
    "extensions" => [
        "credProps" => true
    ]
];

// Generate a response to the registration challenge
$attestation = $authenticator->getAttestation($registrationChallenge);
```

Generate a response to an authentication challenge:

```php
// Sample authentication challenge. See examples/webauthnio_login.php for a complete example.
$authChallenge = [
    "challenge" => "RzckEwPCCFGmO-lkYs_z15YCKAsEcoW49X2DSuuCzL2b6iXjozuap5iVnWzenmfhbsTs0-mqKOwkvhbk8uDbRw",
    "timeout" => 60000,
    "rpId" => "webauthn.io",
    "allowCredentials" => [
        [
            "id" => "2h0MoJD7Slojb_SecLOCfKyMDnC-mEDnFeYLTAefaz4",
            "type" => "public-key",
            "transports" => []
        ],
        [
            "id" => "ySHAlkz_D3-MTo2GZwXNRhDVdDLR23oQaSI3cGz-7Hc",
            "type" => "public-key",
            "transports" => []
        ]
    ],
    "userVerification" => "preferred"
];

// Generate a response to the authentication challenge
$assertion = $authenticator->getAssertion(
    $authChallenge['rpId'],
    $authChallenge['allowCredentials'],
    $authChallenge['challenge']
);
```

## Usage

The `webauthn-emulator` library provides a straightforward interface to emulate WebAuthn authenticators. Below are the
primary methods you will use to interact with the library, along with detailed explanations of their parameters.

### Initialization

To begin using the emulator, instantiate the `Authenticator` class with a credential repository that implements
the `RepositoryInterface`. The library includes a `FileRepository` for testing purposes, which you can replace with a
custom repository for different storage solutions.

```php
use WebauthnEmulator\Authenticator;
use WebauthnEmulator\CredentialRepository\FileRepository;

// Instantiate the file repository to store credentials
$storage = new FileRepository('path/to/credential/storage.txt');

// Create the authenticator instance
$authenticator = new Authenticator($storage);
```

### Registration (Attestation)

The `getAttestation` creates a new key pair and generates a response to a WebAuthn registration challenge, simulating
the process of registering a new authenticator with a WebAuthn relying party. Its behavior is similar to sequentially
calling [navigator.credentials.create()](https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create#web_authentication_api)
and [navigator.credentials.get()](https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get#web_authentication_api)
in the browser. Refer to
the [Web Authentication API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API) documentation for
more details.

`getAttestation` accepts the following parameters:

- `registerOptions` (array, required): Contains the registration challenge data from the relying party, including the
  relying party's information, user data, challenge, and other registration options.
- `origin` (string, optional): The origin of the relying party's website. It defaults to an origin constructed from
  the `rpId` if omitted.
- `extra` (array, optional): Additional data to include in the `clientDataJSON` object. If omitted, only `type`, `origin`,
  and `challenge` are included.

Returns an array similar to [PublicKeyCredential](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential),

```php
$registrationChallenge = [
    // ... (challenge data provided by the relying party)
];

// Generate a response to the registration challenge
$attestation = $authenticator->getAttestation(
    registerOptions: $registrationChallenge,
    origin: 'https://service.example.com', // optional
    extra: ['crossOrigin' => false] // optional
);

echo(json_encode($attestation, JSON_PRETTY_PRINT));

/* Output:
{
    "id": "HB_Pkygg...LQK3WkA",
    "rawId": "HB\/Pkygg...LQK3WkA=",
    "response": {
        "clientDataJSON": "eyJ0e...pbyJ9",
        "attestationObject": "o2Nmb...y4kw="
    },
    "type": "public-key"
}
*/
```

### Authentication (Assertion)

The `getAssertion` method generates a response to a WebAuthn authentication challenge, simulating the process of logging
in with a previously registered key. Its behavior is similar to calling the
browser's [navigator.credentials.get()](https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get#web_authentication_api).

`getAssertion` accepts the following parameters:

- `rpId` (string, required): The relying party identifier, typically the domain name of the relying party's website.
- `credentialIds` (string|array|null, optional): A single credential ID, an array of credential descriptors, or null.
  It identifies which credentials are eligible for authentication. If null or omitted, any available credential for
  the `rpId` may be used.
- `challenge` (string, required): A base64 or base64url encoded challenge from the relying party to prevent replay
  attacks.
- `origin` (string, optional): The origin of the relying party's website. It defaults to an origin constructed from
  the `rpId` if omitted.
- `extra` (array, optional): Additional data to include in the `clientDataJSON` object. If omitted, only `type`, `origin`,
  and `challenge` are included.

Returns an array similar to [PublicKeyCredential](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential),
the output
of [navigator.credentials.get()](https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get#web_authentication_api)
in the browser.

```php
$authChallenge = [
    // ... (challenge data provided by the relying party)
];

// Generate a response to the authentication challenge
$assertion = $authenticator->getAssertion(
    rpId: $authChallenge['rpId'],
    credentialIds: $authChallenge['allowCredentials'],
    challenge: $authChallenge['challenge']
    origin: 'https://service.example.com', // optional
    extra: ['crossOrigin' => false] // optional
);

echo(json_encode($assertion, JSON_PRETTY_PRINT));

/* Output:
{
    "id": "HB_Pkygg...LQK3WkA",
    "rawId": "HB\/Pkygg...LQK3WkA=",
    "response": {
        "authenticatorData": "E4Mf1...AAA==",
        "clientDataJSON": "eyJ0e...pbyJ9",
        "signature": "MEYCI...lzwEj",
        "userHandle": "ZmRmM...mZDk2"
    },
    "type": "public-key"
}
*/

```

### Base64url vs Base64 Encoding

WebAuthn servers often use base64url encoding to represent binary data in a URL-safe format. This encoding is similar to
standard base64 but uses different characters for padding and to represent the 62nd and 63rd values in the index table.
Specifically, base64url encoding replaces `+` with `-`, `/` with `_`, and omits the padding character `=`. This makes it
suitable for use in URLs and filenames without requiring additional encoding.

Different WebAuthn server implementations vary in their use of base64url encoding. Some use base64url-encoded
strings for 'id' or 'challenge' fields, while others use standard base64 encoding or a mix of both. This lack of
consistency puts the burden to figure out which encoding is used by a particular server and to convert the data
accordingly on the developer.

The `webauthn-emulator` library provides two utility methods to handle these encoding variations:

- `base64Normal2Url`: Converts standard base64-encoded strings or arrays to base64url encoding. This method is useful
  when you need to send data to a server that expects base64url-encoded strings.

- `base64Url2Normal`: Converts base64url-encoded strings or arrays back to standard base64 encoding with padding. This
  method is helpful when you receive data from a server that uses base64url encoding, before feeding it to the emulator.

These methods can be applied recursively to arrays, making it easy to encode or decode all elements within an array.

#### Usage of Base64url Encoding/Decoding Methods

When interacting with a WebAuthn server, you may need to encode or decode the 'id', 'challenge', or other binary data
fields. Here's how you can use the provided methods:

With single strings:

```php
use WebauthnEmulator\Authenticator;

// Example of recoding a standard base64 string to base64url
echo Authenticator::base64Normal2Url('wib1OPW9EkDeiwUoyTgJ1+PpFG4dljeXodqRX15DG+gBAAAABQ=='); 
// Output: wib1OPW9EkDeiwUoyTgJ1-PpFG4dljeXodqRX15DG-gBAAAABQ

// Example of recoding a base64url string to standard base64
echo Authenticator::base64Url2Normal('wib1OPW9EkDeiwUoyTgJ1-PpFG4dljeXodqRX15DG-gBAAAABQ');
// Output: wib1OPW9EkDeiwUoyTgJ1+PpFG4dljeXodqRX15DG+gBAAAABQ==
```

With arrays:

```php
use WebauthnEmulator\Authenticator;

$input = [
    "id" => "HB_PkyggPmHCHbcYyQCfLXTakdmq3WGCcOBjLQK3WkA", // already base64url-encoded
    "rawId" => "HB/PkyggPmHCHbcYyQCfLXTakdmq3WGCcOBjLQK3WkA=", // standard base64
];

// Example of recoding an array of standard base64 strings to base64url
$base64urlArray = Authenticator::base64Normal2Url($input);
/* Result:
[
  "id" => "HB_PkyggPmHCHbcYyQCfLXTakdmq3WGCcOBjLQK3WkA", // left as is
  "rawId" => "HB_PkyggPmHCHbcYyQCfLXTakdmq3WGCcOBjLQK3WkA", // recoded to base64url
]
*/ 


// Example of recoding an array of base64url to standard base64
$base64Array = Authenticator::base64Url2Normal($input);
/* Result:
[
  "id" => "HB/PkyggPmHCHbcYyQCfLXTakdmq3WGCcOBjLQK3WkA=", // recoded to standard base64
  "rawId" => "HB/PkyggPmHCHbcYyQCfLXTakdmq3WGCcOBjLQK3WkA=", // left as is
]
*/
```

By using these methods, you can ensure that the data you send and receive from WebAuthn servers is correctly encoded,
regardless of the server's specific implementation details.

## More Examples

For more detailed examples of how to use `webauthn-emulator` to simulate WebAuthn registration and authentication
processes, refer to the [examples](examples) directory in the repository:

- [webauthnio_reg.php](examples/webauthnio_reg.php): Registration with a webauthn.io demo server.
- [webauthnio_login.php](examples/webauthnio_login.php): Login with a webauthn.io demo server.
- [yubico_reg.php](examples/yubico_reg.php): Registration with a Yubico demo server (non-standard query structure).
- [yubico_login.php](examples/yubico_login.php): Login with a Yubico demo server (non-standard query structure).
- [lubuch_reg.php](examples/lubuch_reg.php): Registration with a Lubu.ch demo server (non-standard base64url/binary
  encoding).
- [lubuch_login.php](examples/lubuch_login.php): Login with a Lubu.ch demo server (non-standard base64url/binary
  encoding).
- [quadoio_reg.php](examples/quadoio_reg.php): Registration with a Quado demo server (custom origins and additional
  data).
- [quadoio_login.php](examples/quadoio_login.php): Login with a Quado demo server (custom origins and additional data).

Each server has its own peculiarities, so the examples demonstrate how to handle different scenarios, such as
non-standard base64url encoding, custom origins, and additional data.

## Storing Credentials

The `webauthn-emulator` relies on a credential repository to store and manage credentials. By default, an example
implementation using a file-based repository (`FileRepository`) is provided. However, you can implement your own
repository to store credentials in other places, such as a database by adhering to the `RepositoryInterface`.

Here's an example of using the provided `FileRepository`:

```php
use WebauthnEmulator\CredentialRepository\FileRepository;

// Path to the JSON file that will store the credentials
$storagePath = 'path/to/credential/storage.txt';

// Create a new FileRepository instance
$storage = new FileRepository($storagePath);
```

To create a custom repository, implement the `RepositoryInterface`:

```php
use WebauthnEmulator\CredentialRepository\RepositoryInterface;
use WebauthnEmulator\CredentialInterface;

class CustomRepository implements RepositoryInterface {
    // Implement the required methods
    public function save(CredentialInterface $credential): static {
        // Logic to save the credential
    }

    public function get(string $rpId): array {
        // Logic to retrieve credentials by rpId
    }

    public function getById(string $rpId, string $id): CredentialInterface {
        // Logic to retrieve a credential by rpId and id
    }
}
```

Replace the `FileRepository` with your custom repository when initializing the `Authenticator`:

```php
use WebauthnEmulator\Authenticator;

// Assuming $customStorage is an instance of your custom repository
$authenticator = new Authenticator($customStorage);
```

This flexibility allows you to integrate the `webauthn-emulator` with various storage backends, such as databases or
cloud storage solutions, depending on your application's requirements.

## Testing

This project uses [PHPUnit](https://phpunit.de/) for testing. The tests are organized into three suites:

- **Unit Tests**: Located in `tests/Unit`, these tests check individual components in isolation and do not require any
  external dependencies or network access.
- **Integration Tests**: Located in `tests/Integration`, these tests verify the interaction between different components
  of the library, such as the `Authenticator` and the `FileRepository`.
- **Feature Tests**: Located in `tests/Feature`, these are end-to-end (E2E) tests that perform full registration and
  login flows against live public WebAuthn demo servers. These tests require an active internet connection and are
  marked with the `@group E2E` annotation. They may occasionally fail due to issues with the external services.

### Setup

Before running the tests, you need to install the development dependencies using Composer:

```bash
composer install
```

### Running Tests

You can run the entire test suite, specific suites, or individual tests using the `phpunit` command from the project
root.

**Run all tests:**

```bash
./vendor/bin/phpunit
```

## Limitations

`webauthn-emulator` is designed to support the core functionalities required for WebAuthn registration and
authentication. However, there are some limitations to be aware of:

- The emulator currently supports only the 'none' attestation format. Other formats like 'packed', 'tpm',
  'android-safetynet', etc., are not supported.
- The library is limited to the ES256 (alg: -7) signing algorithm for public key credentials. Other algorithms like
  RS256 or EdDSA are not currently supported. If you need support for other algorithms, please open an issue or submit a
  pull request.

## Contributing and Reporting Issues

Contributions are welcome! If you'd like to contribute or have found a bug, please submit a pull request or report an
issue on the project's GitHub repository. When contributing, ensure your code follows the project's existing style for
consistency.

For feature requests or bug reports, please check
the [GitHub Issues](https://github.com/vadimpronin/webauthn-emulator/issues) to see if it has already been reported. If not,
create a new issue with a detailed description.

## License

`webauthn-emulator` is open-source software licensed under the MIT License. For more details, see the [LICENSE](LICENSE)
file in the repository.

## Acknowledgments

Special thanks to Rayaz Sultanov ([codeproger](https://github.com/codeproger)) for co-creating `webauthn-emulator`.
```