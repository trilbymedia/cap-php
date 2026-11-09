<?php

declare(strict_types=1);

namespace TrilbyMedia\Cap\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use TrilbyMedia\Cap\{Cap, ChallengeOptions, Config, Prng};
use TrilbyMedia\Cap\Instrumentation\{Encoding, Verifier};
use TrilbyMedia\Cap\Storage\ArrayStorage;

final class ProtocolTest extends TestCase
{
    public function testFormatTwoPowAndInstrumentation(): void
    {
        foreach ([false, true] as $instrumentation) {
            $s = new ArrayStorage();
            $cap = new Cap(new Config($s, $s, challengeCount: 2, challengeSize: 9, challengeDifficulty: 1, instrumentation: $instrumentation, format: 2));
            $c = $cap->createChallenge();
            $this->assertSame(2, $c['format']);
            $this->assertArrayNotHasKey('challenge', $c);
            $this->assertArrayNotHasKey('instrumentation', $c);
            $this->assertCount($instrumentation ? 3 : 2, $c['challenges']);
            $solutions = [];
            foreach (array_slice($c['challenges'], 0, 2) as $ch) {
                $this->assertSame('sha256-pow', $ch['protocol']);
                $this->assertSame(9, strlen($ch['payload']['salt']));
                $this->assertSame('0', $ch['payload']['target']);
                $solutions[] = ['nonce' => self::solve($ch['payload']['salt'], '0')];
            }
            // Upstream format 2 accepts string nonces too.
            $solutions[1]['nonce'] = (string)$solutions[1]['nonce'];
            if ($instrumentation) {
                $meta = $s->readChallenge($c['token'])['instrumentation'];
                $d = Encoding::canonical((object)['v' => 1, 'el' => 0, 'p' => null, 'vp' => null, 'hp' => null, 'ag' => [], 'ce' => 0, 'ia' => null, 'bh' => null]);
                $solutions[] = ['instr' => ['i' => $meta['id'], 'state' => array_combine($meta['vars'], Verifier::boundValues($meta['binding'], $d)), 'd' => $d]];
            }
            $r = $cap->redeemChallengeBody(['token' => $c['token'], 'solutions' => $solutions]);
            $this->assertTrue($r['success']);
            $this->assertTrue($cap->validateToken($r['token']));
            $this->assertFalse($cap->redeemChallenge($c['token'], $solutions)['success']);
        }
    }

    public function testFormatTwoFailureMarkersCannotPass(): void
    {
        foreach ([['blocked' => true], ['timeout' => true], ['error' => 'csp_blocked'], []] as $failure) {
            $s = new ArrayStorage();
            $cap = new Cap(new Config($s, $s, challengeCount: 1, challengeDifficulty: 1, format: 2, instrumentation: true));
            $c = $cap->createChallenge();
            $p = $c['challenges'][0]['payload'];
            $r = $cap->redeemChallenge($c['token'], [['nonce' => self::solve($p['salt'], $p['target'])], $failure]);
            $this->assertFalse($r['success']);
            $this->assertTrue($r['instr_error']);
        }
    }

    public function testPositionalOptionsAndUnstoredChallengeStillWork(): void
    {
        $s = new ArrayStorage();
        $cap = new Cap(new Config($s, $s));
        $c = $cap->createChallenge(new ChallengeOptions(1, 16, 2));
        $this->assertSame(['c' => 1, 's' => 16, 'd' => 2], $c['challenge']);
        $this->assertSame(50, strlen($c['token']));
        $c = $cap->createChallenge(new ChallengeOptions(1, 16, 2, store: false, format: 2));
        $this->assertArrayNotHasKey('token', $c);
        $this->assertSame(2, $c['format']);
    }

    public function testScopeProtectsBothChallengeAndVerificationToken(): void
    {
        $s = new ArrayStorage();
        $a = new Cap(new Config($s, $s, challengeCount: 1, challengeDifficulty: 1, scope: 'a'));
        $b = new Cap(new Config($s, $s, challengeCount: 1, challengeDifficulty: 1, scope: 'b'));
        $c = $a->createChallenge();
        $r = $b->redeemChallenge($c['token'], [0]);
        $this->assertSame('scope_mismatch', $r['reason']);
        $c = $a->createChallenge();
        $salt = Prng::generate($c['token'] . '1', 32);
        $target = Prng::generate($c['token'] . '1d', 1);
        $r = $a->redeemChallenge($c['token'], [self::solve($salt, $target)]);
        $this->assertTrue($r['success']);
        $this->assertFalse($b->validateToken($r['token']));
        $this->assertTrue($a->validateToken($r['token']));
    }

    public static function invalidParams(): iterable
    {
        foreach ([0, -1, 1001] as $v) yield 'count ' . $v => [new ChallengeOptions(challengeCount: $v)];
        foreach ([0, 257] as $v) yield 'size ' . $v => [new ChallengeOptions(challengeSize: $v)];
        foreach ([0, 17] as $v) yield 'difficulty ' . $v => [new ChallengeOptions(challengeDifficulty: $v)];
        yield 'format' => [new ChallengeOptions(format: 3)];
    }

    #[DataProvider('invalidParams')]
    public function testParameterBounds(ChallengeOptions $opts): void
    {
        $s = new ArrayStorage();
        $this->expectException(\InvalidArgumentException::class);
        (new Cap(new Config($s, $s)))->createChallenge($opts);
    }

    public static function invalidSolutions(): iterable
    {
        yield 'extra' => [[0, 0]];
        yield 'empty' => [[]];
        yield 'associative' => [['x' => 0]];
        yield 'negative' => [[-1]];
        yield 'unsafe JS integer' => [[9_007_199_254_740_992]];
        yield 'float' => [[1.0]];
        yield 'string' => [['1']];
    }

    #[DataProvider('invalidSolutions')]
    public function testRejectsMalformedLegacySolutions(array $solutions): void
    {
        $s = new ArrayStorage();
        $cap = new Cap(new Config($s, $s, challengeCount: 1, challengeDifficulty: 1));
        $c = $cap->createChallenge();
        $this->assertFalse($cap->redeemChallenge($c['token'], $solutions)['success']);
    }

    public function testGuardRecordsCannotBeDeletedThroughRedeem(): void
    {
        $s = new ArrayStorage();
        $cap = new Cap(new Config($s, $s));
        $record = ['scope' => 'a', 'level' => 1, 'expires' => PHP_INT_MAX];
        $s->storeChallenge('grav-bind:abc', $record);
        $this->assertFalse($cap->redeemChallenge('grav-bind:abc', [0])['success']);
        $this->assertSame($record, $s->readChallenge('grav-bind:abc'));
    }

    public function testBodyHelperRejectsInvalidTypes(): void
    {
        $s = new ArrayStorage();
        $cap = new Cap(new Config($s, $s));
        foreach ([[], ['token' => [], 'solutions' => []], ['token' => 'x', 'solutions' => 'y']] as $body) {
            $this->assertSame(['success' => false, 'message' => 'Invalid body'], $cap->redeemChallengeBody($body));
        }
        $this->assertFalse($cap->validateToken('abc:def:extra'));
    }

    private static function solve(string $salt, string $target): int
    {
        for ($n = 0; ; $n++) if (str_starts_with(hash('sha256', $salt . $n), $target)) return $n;
    }
}
