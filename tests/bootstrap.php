<?php

/**
 * Test bootstrap file for WebAuthn Emulator
 *
 * This file is executed before PHPUnit runs any tests.
 * It sets up the test environment and autoloading.
 */

// Load composer autoloader
require_once dirname(__DIR__) . '/vendor/autoload.php';

// Set default timezone to avoid warnings in tests
date_default_timezone_set('UTC');

// Error reporting for tests
error_reporting(E_ALL);
ini_set('display_errors', '1');

// Ensure consistent floating point precision
ini_set('precision', '14');
ini_set('serialize_precision', '14');

// Create temp directory for test files if it doesn't exist
$tempDir = sys_get_temp_dir() . '/webauthn-emulator-tests';
if (!is_dir($tempDir)) {
    mkdir($tempDir, 0777, true);
}

// Register cleanup function to remove temp files after tests
register_shutdown_function(function() use ($tempDir) {
    if (is_dir($tempDir)) {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($tempDir, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        
        foreach ($files as $fileinfo) {
            $todo = ($fileinfo->isDir() ? 'rmdir' : 'unlink');
            @$todo($fileinfo->getRealPath());
        }
        
        @rmdir($tempDir);
    }
});

// Define test constants
define('WEBAUTHN_TEST_TEMP_DIR', $tempDir);