<?php

declare(strict_types=1);

namespace TrilbyMedia\Cap\Tests;

use PHPUnit\Framework\TestCase;
use TrilbyMedia\Cap\Storage\DirectoryStorage;

final class DirectoryStorageTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/cap-dir-' . bin2hex(random_bytes(8));
    }

    protected function tearDown(): void
    {
        AtomicStorageTest::removeTree($this->dir);
    }

    public function testRoundtripsAndConsumesOnce(): void
    {
        $s = new DirectoryStorage($this->dir);
        $record = ['challenge' => ['c' => 2], 'expires' => PHP_INT_MAX];
        $s->storeChallenge('abc', $record);
        $this->assertSame($record, $s->readChallenge('abc'));
        $this->assertSame($record, (new DirectoryStorage($this->dir))->readChallenge('abc'));
        $this->assertSame($record, $s->consumeChallenge('abc'));
        $this->assertNull($s->consumeChallenge('abc'));
        $this->assertNull($s->readChallenge('abc'));

        $s->storeToken('id:hash', 123456);
        $this->assertSame(123456, $s->readToken('id:hash'));
        $this->assertSame(123456, $s->consumeToken('id:hash'));
        $this->assertNull($s->consumeToken('id:hash'));

        $s->storeChallenge('x', ['expires' => 1]);
        $s->deleteChallenge('x');
        $s->deleteChallenge('x');
        $this->assertNull($s->readChallenge('x'));
        $s->storeToken('y', 1);
        $s->deleteToken('y');
        $this->assertNull($s->readToken('y'));
    }

    public function testStoreReplacesAndKeysNeverBecomePaths(): void
    {
        $s = new DirectoryStorage($this->dir);
        $s->storeChallenge('../../escape', ['n' => 1, 'expires' => PHP_INT_MAX]);
        $s->storeChallenge('../../escape', ['n' => 2, 'expires' => PHP_INT_MAX]);
        $this->assertSame(2, $s->readChallenge('../../escape')['n']);
        $files = glob($this->dir . '/c/*/*');
        $this->assertCount(1, $files);
        $this->assertMatchesRegularExpression('#/c/[a-f0-9]{2}/[a-f0-9]{64}$#', $files[0]);
    }

    public function testSweepRemovesOnlyExpiredRecordsAndLeftovers(): void
    {
        $s = new DirectoryStorage($this->dir, 0);
        $nowMs = (int)(microtime(true) * 1000);
        $s->storeChallenge('old', ['expires' => $nowMs - 5000]);
        $s->storeChallenge('live', ['expires' => $nowMs + 60000]);
        $s->storeToken('old', $nowMs - 5000);
        $s->storeToken('live', $nowMs + 60000);

        // A record whose mtime couldn't be set to its expiry is judged by its contents.
        $s->storeChallenge('live-old-mtime', ['expires' => $nowMs + 60000]);
        $path = $this->dir . '/c/' . substr(hash('sha256', 'live-old-mtime'), 0, 2) . '/' . hash('sha256', 'live-old-mtime');
        touch($path, time() - 3600);

        // A claimed file younger than a minute may belong to a request still running.
        $shard = dirname($path);
        file_put_contents($shard . '/' . basename($path) . '.0123456789ab', 'x');

        $s->deleteExpiredChallenges();
        $s->deleteExpiredTokens();

        $this->assertNull($s->readChallenge('old'));
        $this->assertNotNull($s->readChallenge('live'));
        $this->assertNotNull($s->readChallenge('live-old-mtime'));
        $this->assertNull($s->readToken('old'));
        $this->assertNotNull($s->readToken('live'));
        $this->assertFileExists($shard . '/' . basename($path) . '.0123456789ab');
    }

    public function testSweepIsThrottled(): void
    {
        $s = new DirectoryStorage($this->dir, 300);
        $nowMs = (int)(microtime(true) * 1000);
        $s->storeChallenge('a', ['expires' => $nowMs - 1000]);
        $s->deleteExpiredChallenges();
        $this->assertNull($s->readChallenge('a'));

        $s->storeChallenge('b', ['expires' => $nowMs - 1000]);
        $s->deleteExpiredChallenges();
        $this->assertNotNull($s->readChallenge('b'), 'second sweep within the interval is skipped');

        touch($this->dir . '/.swept-c', time() - 301);
        $s->deleteExpiredChallenges();
        $this->assertNull($s->readChallenge('b'));
    }

    public function testDamagedRecordsReadAsMissing(): void
    {
        $s = new DirectoryStorage($this->dir);
        $s->storeChallenge('c', ['expires' => PHP_INT_MAX]);
        $s->storeToken('t', 5);
        foreach (['c/' . hash('sha256', 'c'), 't/' . hash('sha256', 't')] as $rel) {
            [$kind, $hash] = explode('/', $rel);
            file_put_contents("{$this->dir}/{$kind}/" . substr($hash, 0, 2) . "/{$hash}", '{broken');
        }
        $this->assertNull($s->readChallenge('c'));
        $this->assertNull($s->consumeChallenge('c'));
        $this->assertNull($s->readToken('t'));
    }

    public function testUnwritableDirectoryThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        file_put_contents($this->dir, 'not a directory');
        try {
            new DirectoryStorage($this->dir . '/sub');
        } finally {
            unlink($this->dir);
        }
    }
}
