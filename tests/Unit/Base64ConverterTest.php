<?php

namespace WebauthnEmulator\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebauthnEmulator\Authenticator;

class Base64ConverterTest extends TestCase
{
    /** @dataProvider base64NormalProvider */
    public function testBase64Normal2Url($input, $expected)
    {
        $this->assertSame($expected, Authenticator::base64Normal2Url($input));
    }

    /** @dataProvider base64UrlProvider */
    public function testBase64Url2Normal($input, $expected)
    {
        $this->assertSame($expected, Authenticator::base64Url2Normal($input));
    }

    public function base64NormalProvider(): array
    {
        return [
            'standard string with plus' => ['SGVsbG8+V29ybGQ=', 'SGVsbG8-V29ybGQ'],
            'array of strings' => [
                ['SGVsbG8+V29ybGQ=', 'dGVzdD90ZXN0'],
                ['SGVsbG8-V29ybGQ', 'dGVzdD90ZXN0']
            ],
            'already url safe' => ['a-b_c', 'a-b_c'],
            'not base64' => ['not_base64!', 'not_base64!'],
            'string with slash' => ['/w==', '_w'],
            'string with plus and slash' => ['+/8=', '-_8'],
        ];
    }

    public function base64UrlProvider(): array
    {
        return [
            'url safe string with dash' => ['SGVsbG8-V29ybGQ', 'SGVsbG8+V29ybGQ='],
            'array of strings' => [
                ['SGVsbG8-V29ybGQ', 'dGVzdD90ZXN0'],
                ['SGVsbG8+V29ybGQ=', 'dGVzdD90ZXN0']
            ],
            'already normal base64' => ['SGVsbG8+V29ybGQ=', 'SGVsbG8+V29ybGQ='],
            'not base64' => ['not_base64_url!', 'not_base64_url!'],
            'url safe string with underscore' => ['_w', '/w=='],
            'url safe string with dash and underscore' => ['-_8', '+/8='],
        ];
    }
}
