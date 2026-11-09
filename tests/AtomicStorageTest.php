<?php

declare(strict_types=1);

namespace TrilbyMedia\Cap\Tests;

use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface;
use TrilbyMedia\Cap\{Cap, Config, Prng};
use TrilbyMedia\Cap\Storage\{ArrayStorage, FilesystemStorage, Psr16Storage};

final class AtomicStorageTest extends TestCase
{
    public function testConcurrentRedeemAndValidationHaveExactlyOneWinner(): void
    {
        $dir = sys_get_temp_dir() . '/cap-concurrency-' . bin2hex(random_bytes(8));
        mkdir($dir);
        try {
            $s = new FilesystemStorage($dir);
            $cap = new Cap(new Config($s, $s, challengeCount: 1, challengeDifficulty: 1));
            $c = $cap->createChallenge();
            $salt = Prng::generate($c['token'] . '1', 32);
            $target = Prng::generate($c['token'] . '1d', 1);
            for ($n = 0; !str_starts_with(hash('sha256', $salt . $n), $target); $n++) {}
            $results = $this->children($dir, $c['token'], $n, false);
            $winners = array_values(array_filter($results, static fn ($r) => $r['success']));
            $this->assertCount(1, $winners);
            for ($i = 0; $i < 8; $i++) {
                $this->assertSame(['n' => $i, 'expires' => PHP_INT_MAX], $s->readChallenge('rate-' . $i));
            }
            $validated = $this->children($dir, $winners[0]['token'], 0, true);
            $this->assertCount(1, array_filter($validated, static fn ($r) => $r['success']));
        } finally {
            foreach (glob($dir . '/*') as $file) unlink($file);
            rmdir($dir);
        }
    }

    private function children(string $dir, string $token, int $nonce, bool $validate): array
    {
        $autoload = dirname(__DIR__) . '/vendor/autoload.php';
        $script = <<<'CODE'
require $argv[1];
$s = new TrilbyMedia\Cap\Storage\FilesystemStorage($argv[2]);
$c = new TrilbyMedia\Cap\Cap(new TrilbyMedia\Cap\Config($s, $s, disableAutoCleanup: true));
while (true) { clearstatcache(true, $argv[3]); if (is_file($argv[3])) break; usleep(1000); }
if ($argv[7] === '1') {
    $r = ['success' => $c->validateToken($argv[4])];
} else {
    $s->storeChallenge('rate-' . $argv[6], ['n' => (int)$argv[6], 'expires' => PHP_INT_MAX]);
    $r = $c->redeemChallenge($argv[4], [(int)$argv[5]]);
}
echo json_encode($r);
CODE;
        $barrier = $dir . '/start-' . ($validate ? 'validate' : 'redeem');
        $children = [];
        for ($i = 0; $i < 8; $i++) {
            $process = proc_open([PHP_BINARY, '-r', $script, $autoload, $dir, $barrier, $token, (string)$nonce, (string)$i, $validate ? '1' : '0'], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            $this->assertIsResource($process);
            fclose($pipes[0]);
            $children[] = [$process, $pipes];
        }
        touch($barrier);
        $results = [];
        foreach ($children as [$process, $pipes]) {
            $output = stream_get_contents($pipes[1]);
            $errors = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            $this->assertSame(0, proc_close($process), $errors);
            $this->assertSame('', $errors);
            $results[] = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
        }
        return $results;
    }

    public function testArbitraryRecordsSurviveAllBackends(): void
    {
        $dir = sys_get_temp_dir() . '/cap-records-' . bin2hex(random_bytes(8));
        $values = [];
        $cache = $this->createMock(CacheInterface::class);
        $cache->method('set')->willReturnCallback(static function ($key, $value, $ttl) use (&$values): bool {
            TestCase::assertLessThanOrEqual(64, strlen($key));
            TestCase::assertGreaterThanOrEqual(1, $ttl);
            $values[$key] = $value;
            return true;
        });
        $cache->method('get')->willReturnCallback(static function ($key, $default = null) use (&$values) { return $values[$key] ?? $default; });
        $cache->method('delete')->willReturnCallback(static function ($key) use (&$values): bool { unset($values[$key]); return true; });
        try {
            foreach ([new ArrayStorage(), new FilesystemStorage($dir), new Psr16Storage($cache)] as $s) {
                $record = ['n' => 5, 'scope' => ['a', 'b'], 'expires' => PHP_INT_MAX];
                $s->storeChallenge('grav-rate:example', $record);
                $this->assertSame($record, $s->readChallenge('grav-rate:example'));
                $s->deleteExpiredChallenges();
                $this->assertSame($record, $s->readChallenge('grav-rate:example'));
                $s->deleteChallenge('grav-rate:example');
                $this->assertNull($s->readChallenge('grav-rate:example'));
                $cap = new Cap(new Config($s, $s, challengeCount: 1, challengeDifficulty: 1));
                $c = $cap->createChallenge();
                $salt = Prng::generate($c['token'] . '1', 32);
                $target = Prng::generate($c['token'] . '1d', 1);
                for ($n = 0; !str_starts_with(hash('sha256', $salt . $n), $target); $n++) {}
                $r = $cap->redeemChallenge($c['token'], [$n]);
                $this->assertTrue($r['success']);
                $this->assertTrue($cap->validateToken($r['token'], keepToken: true));
                $this->assertTrue($cap->validateToken($r['token']));
                $this->assertFalse($cap->validateToken($r['token']));
            }
        } finally {
            foreach (glob($dir . '/*') as $file) unlink($file);
            rmdir($dir);
        }
    }

    public function testCorruptFilesystemStateFailsWithoutOverwriting(): void
    {
        $dir = sys_get_temp_dir() . '/cap-corrupt-' . bin2hex(random_bytes(8));
        mkdir($dir);
        file_put_contents($dir . '/challenges.json', '{broken');
        try {
            $s = new FilesystemStorage($dir);
            try {
                $s->storeChallenge('test', ['expires' => PHP_INT_MAX]);
                $this->fail('Corrupt data must fail closed');
            } catch (\JsonException $e) {
                $this->assertSame('{broken', file_get_contents($dir . '/challenges.json'));
            }
        } finally {
            foreach (glob($dir . '/*') as $file) unlink($file);
            rmdir($dir);
        }
    }
}
