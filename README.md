# webauthn-emulator

`webauthn-emulator` is a PHP library that emulates WebAuthn-compatible authenticators. It enables developers to
integrate WebAuthn client-side authentication into their applications without the need for physical security devices
like YubiKeys, Touch ID, Face ID, Windows Hello, etc.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [More Examples](#more-examples)
- [Storing Credentials](#storing-credentials)
- [Supported Features and Limitations](#supported-features-and-limitations)
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
$storage = new FileRepository('path/to/credential/storage.json');

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

## More Examples

For more detailed examples of how to use `webauthn-emulator` to simulate WebAuthn registration and authentication
processes, refer to the `examples` directory in the repository:

- `examples/webauthnio_reg.php`: Simulate the registration process with a WebAuthn server.
- `examples/webauthnio_login.php`: Simulate the login process with a WebAuthn server.
- `examples/yubico_reg.php`: Simulate the registration process with a Yubico server.
- `examples/yubico_login.php`: Simulate the login process with a Yubico server.

These examples provide a comprehensive guide on constructing full registration and authentication payloads and
interacting with WebAuthn servers.

## Storing Credentials

The `webauthn-emulator` relies on a credential repository to store and manage credentials. By default, an example
implementation using a file-based repository (`FileRepository`) is provided. However, you can implement your own
repository to store credentials in other places, such as a database by adhering to the `RepositoryInterface`.

Here's an example of using the provided `FileRepository`:

```php
use WebauthnEmulator\CredentialRepository\FileRepository;

// Path to the JSON file that will store the credentials
$storagePath = 'path/to/credential/storage.json';

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

## Supported Features and Limitations

`webauthn-emulator` is designed to support the core functionalities required for WebAuthn registration and
authentication. However, there are some limitations to be aware of.

### Supported Features:

- Emulation of WebAuthn registration (attestation) and authentication (assertion) processes.
- Generation of attestation and assertion objects according to the WebAuthn specification.
- Flexible integration with custom credential repositories for storing keys.

### Limitations:

- The emulator currently supports only the 'none' attestation format. Other formats like 'packed', 'tpm',
  'android-safetynet', etc., are not supported.
- The library is limited to the ES256 signing algorithm for public key credentials. Other algorithms like RS256 or EdDSA
  are not currently supported. If you need support for other algorithms, please open an issue or submit a pull request.
- The emulator does not simulate the full range of authenticator capabilities, such as user presence or user
  verification checks.

## Contributing and Reporting Issues

We welcome contributions to the `webauthn-emulator`. If you'd like to contribute or have found a bug, please submit a
pull request or report an issue on the project's GitHub repository. When contributing, ensure your code follows the
project's existing style for consistency.

For feature requests or bug reports, please check
the [GitHub Issues](https://github.com/pronin/webauthn-emulator/issues) to see if it has already been reported. If not,
create a new issue with a detailed description.

## License

`webauthn-emulator` is open-source software licensed under the MIT License. For more details, see the [LICENSE](LICENSE)
file in the repository.

## Acknowledgments

Special thanks to Rayaz Sultanov ([Rayazik](https://github.com/Rayazik)) for co-creating `webauthn-emulator`.

