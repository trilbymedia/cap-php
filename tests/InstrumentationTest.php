<?php

declare(strict_types=1);

namespace TrilbyMedia\Cap\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use TrilbyMedia\Cap\{Cap, Config, ChallengeOptions, InstrumentationOptions, Prng};
use TrilbyMedia\Cap\Instrumentation\{Detector, Encoding, Generator, Verifier};
use TrilbyMedia\Cap\Storage\ArrayStorage;

final class InstrumentationTest extends TestCase
{
    public static function detectorVectors(): iterable
    {
        foreach (self::vectors()['detect'] as $v) {
            yield $v['name'] => [$v];
        }
    }

    public static function verifierVectors(): iterable
    {
        foreach (self::vectors()['verify'] as $v) {
            yield $v['name'] => [$v];
        }
    }

    private static function vectors(): array
    {
        return json_decode(file_get_contents(__DIR__ . '/fixtures/parity-vectors.json'), true, 512, JSON_THROW_ON_ERROR);
    }

    #[DataProvider('detectorVectors')]
    public function testUpstreamDetectorVectors(array $v): void
    {
        $this->assertSame($v['result'], Detector::detect($v['input']));
    }

    #[DataProvider('verifierVectors')]
    public function testUpstreamVerifierVectors(array $v): void
    {
        $actual = Verifier::verify($v['meta'], $v['payload'], $v['now']);
        foreach ($v['result'] as $key => $value) {
            $this->assertSame($value, $actual[$key] ?? null, $key);
        }
    }

    public function testUnicodeBoundHashMatchesUpstream(): void
    {
        foreach (self::vectors()['encoding'] as $v) {
            $this->assertSame($v['hash'], Verifier::boundValues(['pv' => [0, 0, 0, 0], 'sl' => [0, 0, 0, 0], 'hs' => [89123456, 987654321], 'j' => [0, 2]], $v['value']));
        }
    }

    public function testCanonicalNumbersMatchJavascript(): void
    {
        foreach (['1e-7', '0.000001', '100000000000000000000', '1e+21', '0', '3.1415'] as $json) {
            $this->assertSame($json, Encoding::canonical(json_decode($json)));
        }
    }

    public function testGeneratedProgramsAreUniqueAndKeepAnswersPrivate(): void
    {
        $storage = new ArrayStorage();
        $cap = new Cap(new Config($storage, $storage, instrumentation: true));
        $first = $cap->createChallenge();
        $second = $cap->createChallenge();
        $this->assertNotSame($first['instrumentation'], $second['instrumentation']);
        $this->assertSame(['challenge', 'token', 'expires', 'instrumentation'], array_keys($first));
        $meta = $storage->readChallenge($first['token'])['instrumentation'];
        $this->assertArrayHasKey('binding', $meta);
        $this->assertArrayNotHasKey('instrumentation', $meta);
        $script = gzinflate(base64_decode($first['instrumentation']));
        $this->assertStringNotContainsString('__CAP_', $script);
        $this->assertStringContainsString('cap:ready', $script);
        $this->assertStringContainsString('cap:finalize', $script);
        $this->assertStringNotContainsString('binding', $script);
    }

    public function testPerChallengeDisableAndDefaultCompatibility(): void
    {
        $s = new ArrayStorage();
        $cap = new Cap(new Config($s, $s, instrumentation: true));
        $this->assertArrayNotHasKey('instrumentation', $cap->createChallenge(new ChallengeOptions(instrumentation: false)));
        $cap = new Cap(new Config($s, $s));
        $this->assertArrayNotHasKey('instrumentation', $cap->createChallenge());
        $this->assertArrayHasKey('instrumentation', $cap->createChallenge(new ChallengeOptions(instrumentation: new InstrumentationOptions(blockAutomatedBrowsers: true))));
    }

    public static function failureMarkers(): iterable
    {
        yield 'missing' => [[], 'instr_missing'];
        yield 'blocked' => [['instr_blocked' => true], 'instr_failed'];
        yield 'timeout' => [['instr_timeout' => true], 'instr_timeout'];
        foreach (['csp_blocked' => 'instr_csp_blocked', 'csp_script_blocked' => 'instr_csp_blocked', 'natives_tampered' => 'instr_natives_tampered', 'env_failed' => 'instr_env_failed', 'script_failed' => 'instr_script_failed', 'unknown' => 'instr_failed'] as $code => $reason) {
            yield $code => [['instr_error' => $code], $reason];
        }
    }

    #[DataProvider('failureMarkers')]
    public function testMarkersAlwaysFailEvenAlongsideValidOutput(array $markers, string $reason): void
    {
        $s = new ArrayStorage();
        $cap = new Cap(new Config($s, $s, challengeCount: 1, challengeDifficulty: 1, instrumentation: true));
        $c = $cap->createChallenge();
        $body = ['token' => $c['token'], 'solutions' => self::solve($c)];
        if ($markers) {
            $body['instr'] = self::makeOutput($s->readChallenge($c['token'])['instrumentation']);
        }
        $r = $cap->redeemChallengeBody($body + $markers);
        $this->assertFalse($r['success']);
        $this->assertTrue($r['instr_error']);
        $this->assertSame($reason, $r['reason']);
        $this->assertNull($s->readChallenge($c['token']));
    }

    public function testInstrumentationRoundTripAndTampering(): void
    {
        $s = new ArrayStorage();
        $cap = new Cap(new Config($s, $s, challengeCount: 1, challengeDifficulty: 1, instrumentation: true));
        foreach ([false, true] as $tamper) {
            $c = $cap->createChallenge();
            $output = self::makeOutput($s->readChallenge($c['token'])['instrumentation']);
            if ($tamper) {
                $output['d'] = str_replace('"ce":0', '"ce":1', $output['d']);
            }
            $r = $cap->redeemChallenge($c['token'], self::solve($c), ['instr' => $output]);
            $this->assertSame(!$tamper, $r['success']);
            if (!$tamper) {
                $this->assertTrue($cap->validateToken($r['token']));
                $this->assertFalse($cap->validateToken($r['token']));
            }
        }
    }

    private static function makeOutput(array $meta): array
    {
        $data = (object)['v' => 1, 'el' => 0, 'p' => null, 'vp' => null, 'hp' => null, 'ag' => [], 'ce' => 0, 'ia' => null, 'bh' => null];
        $d = Encoding::canonical($data);
        return ['i' => $meta['id'], 'state' => array_combine($meta['vars'], Verifier::boundValues($meta['binding'], $d)), 'd' => $d];
    }

    private static function solve(array $c): array
    {
        $salt = Prng::generate($c['token'] . '1', $c['challenge']['s']);
        $target = Prng::generate($c['token'] . '1d', $c['challenge']['d']);
        for ($n = 0; ; $n++) {
            if (str_starts_with(hash('sha256', $salt . $n), $target)) {
                return [$n];
            }
        }
    }
}
