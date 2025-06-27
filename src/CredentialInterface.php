<?php

declare(strict_types=1);

namespace WebauthnEmulator;

use JetBrains\PhpStorm\ArrayShape;

interface CredentialInterface
{
    /**
     * @doc RFC 8152
     * @return string
     */
    public function getCoseKey(): string;
    public function getRpId(): string;
    public function getRpIdHash(): string;
    public function getPackedSignCount(): string;
    public function getPackedIdLength(): string;
    public function getId(): string;
    public function getUserHandle(): string;
    #[ArrayShape([
        'id' => "string",
        'privateKey' => "string",
        'rpId' => "string",
        'userHandle' => "string",
        'signCount' => "int"
    ])]
    public function toArray(): array;
    public static function fromArray(array $credentialData): static;
    public function incrementSignCount(): static;
}
