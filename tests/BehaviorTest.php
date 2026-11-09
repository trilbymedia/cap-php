<?php

declare(strict_types=1);

namespace TrilbyMedia\Cap\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use TrilbyMedia\Cap\{Cap, Config, BehaviorOptions, Prng};
use TrilbyMedia\Cap\Instrumentation\{Agents, Behavior, Encoding, Policy, Verifier};
use TrilbyMedia\Cap\Storage\ArrayStorage;

final class BehaviorTest extends TestCase
{
    public static function vectors(): iterable
    {
        $all = json_decode(file_get_contents(__DIR__ . '/fixtures/parity-vectors.json'), true, 512, JSON_THROW_ON_ERROR);
        foreach ($all['behavior'] as $v) yield $v['name'] => [$v];
    }

    public static function agents(): iterable
    {
        $all = json_decode(file_get_contents(__DIR__ . '/fixtures/parity-vectors.json'), true, 512, JSON_THROW_ON_ERROR);
        foreach ($all['agents'] as $v) yield $v['name'] => [$v];
    }

    #[DataProvider('vectors')]
    public function testBehaviorMatchesUpstream(array $v): void
    {
        $this->assertSame($v['invalid'], Behavior::validate($v['input']));
        $r = Behavior::analyze($v['input'], $v['ctx']);
        $this->assertSame($v['result'], json_decode(json_encode($r), true));
    }

    #[DataProvider('agents')]
    public function testAgentEvidenceMatchesUpstream(array $v): void
    {
        $found = match ($v['kind']) {
            'trace' => Agents::fromTrace($v['input']),
            'codes' => Agents::fromCodes($v['input']),
            'headers' => Agents::fromHeaders($v['input']),
        };
        $this->assertSame($v['found'], $found);
        $this->assertSame($v['result'], Agents::summarize($found));
    }

    public function testBehaviorPolicyIsCapturedAndEnforced(): void
    {
        foreach ([false, true] as $block) {
            $s = new ArrayStorage();
            $cap = new Cap(new Config($s, $s, challengeCount: 1, challengeDifficulty: 1, behavior: new BehaviorOptions(block: $block)));
            $c = $cap->createChallenge();
            $this->assertTrue($c['behavior']);
            $meta = $s->readChallenge($c['token'])['instrumentation'];
            $this->assertSame($block, $meta['behaviorEnforced']);
            $data = (object)['v' => 1, 'el' => 0, 'p' => null, 'vp' => null, 'hp' => (object)[], 'ag' => [], 'ce' => 0, 'ia' => null, 'bh' => (object)['v' => 1, 'res' => .1, 'now' => 5000, 'vis' => 300, 'last' => 3400, 'us' => -1, 'env' => [1440,820,2,1,0,87,120,60], 'n' => array_fill(0,10,0), 'm' => [], 'k' => [], 'a' => null]];
            $d = Encoding::canonical($data);
            $instr = ['i' => $meta['id'], 'state' => array_combine($meta['vars'], Verifier::boundValues($meta['binding'], $d)), 'd' => $d];
            $salt = Prng::generate($c['token'] . '1', 32);
            $target = Prng::generate($c['token'] . '1d', 1);
            for ($n = 0; !str_starts_with(hash('sha256', $salt . $n), $target); $n++) {}
            $r = $cap->redeemChallengeBody(['token' => $c['token'], 'solutions' => [$n], 'instr' => $instr]);
            $this->assertSame(!$block, $r['success']);
            if ($block) $this->assertSame('behavior_no_interaction', $r['reason']);
            else $this->assertSame('no_interaction', $r['behavior']['verdict']);
        }
    }

    public function testReplayCallbackAndAgentBlocking(): void
    {
        $all = iterator_to_array(self::vectors());
        $trace = $all['human'][0]['input'];
        $calls = 0;
        $verified = ['trace' => $trace, 'agent' => ['all' => ['stagehand'], 'host' => true, 'legacy' => false, 'isolated' => false, 'browser' => null], 'riskFlags' => []];
        $r = Policy::evaluate($verified, (new BehaviorOptions(blockAgents: 'identified'))->policy(), [], static function ($digest, $ttl) use (&$calls) {
            TestCase::assertSame(64, strlen($digest));
            TestCase::assertGreaterThanOrEqual(60000, $ttl);
            $calls++;
            return true;
        }, 1000);
        $this->assertSame(1, $calls);
        $this->assertFalse($r['valid']);
        $this->assertSame('behavior_agent', $r['reason']);
        $this->assertContains('bh_replayed', $r['behavior']['flags']);
    }

    public function testHeadersAreSeparateFromUntrustedBody(): void
    {
        $r = Policy::evaluate([], null, ['user-agent' => 'Claude-Agent/1'], null, 0);
        $this->assertSame('claude-agent', $r['agent']['name']);
        $this->assertFalse($r['agent']['verified']);
        $this->assertContains('agent:claude-agent', $r['riskFlags']);
    }

    public function testInvalidThreshold(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new BehaviorOptions(threshold: NAN);
    }

    public function testInvalidAgentPolicy(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new BehaviorOptions(blockAgents: 'invalid');
    }
}
