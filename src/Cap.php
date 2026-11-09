<?php

declare(strict_types=1);

namespace TrilbyMedia\Cap;

use TrilbyMedia\Cap\Instrumentation\Generator;
use TrilbyMedia\Cap\Instrumentation\Verifier;
use TrilbyMedia\Cap\Instrumentation\Policy;

/**
 * Cap proof-of-work captcha server.
 *
 * Wire-compatible with the official @cap.js/widget. The client widget
 * POSTs to two endpoints you expose:
 *
 *   POST /challenge → Cap::createChallenge() response
 *   POST /redeem    → Cap::redeemChallenge($body['token'], $body['solutions'])
 *
 * When the form is submitted, validate the token the widget put in the
 * form with Cap::validateToken().
 */
final class Cap
{
    private const CLEANUP_INTERVAL_MS = 300_000; // 5 min

    private int $lastCleanupMs = 0;

    public function __construct(private readonly Config $config) {}

    /**
     * Generate a new challenge.
     *
     * @return array{challenge: array{c:int,s:int,d:int}, token?: string, expires: int, instrumentation?: string}
     */
    public function createChallenge(?ChallengeOptions $opts = null): array
    {
        $this->lazyCleanup();

        $challenge = [
            'c' => $opts?->challengeCount       ?? $this->config->challengeCount,
            's' => $opts?->challengeSize        ?? $this->config->challengeSize,
            'd' => $opts?->challengeDifficulty  ?? $this->config->challengeDifficulty,
        ];
        $expiresMs = $opts?->expiresMs ?? $this->config->expiresMs;
        $expires   = $this->nowMs() + $expiresMs;

        if ($opts?->store === false) {
            return ['challenge' => $challenge, 'expires' => $expires];
        }

        $token = $this->randomHex(25);
        $stored = $challenge + ['expires' => $expires];
        $result = ['challenge' => $challenge, 'token' => $token, 'expires' => $expires];
        $instrumentation = $opts?->instrumentation ?? $this->config->instrumentation;
        $behavior = $opts?->behavior ?? $this->config->behavior;
        if ($behavior !== false) {
            $behavior = $behavior === true ? new BehaviorOptions() : $behavior;
            $stored['behavior'] = $behavior->policy();
            $result['behavior'] = true;
        }
        if ($instrumentation !== false || $behavior !== false) {
            $meta = Generator::generate($instrumentation instanceof InstrumentationOptions ? $instrumentation : new InstrumentationOptions(), $this->nowMs(), $expires, $behavior !== false, $behavior !== false && ($behavior->block || $behavior->blockAgents !== false));
            $result['instrumentation'] = $meta['instrumentation'];
            unset($meta['instrumentation']);
            $stored['instrumentation'] = $meta;
        }
        $this->config->challengeStorage->storeChallenge($token, $stored);

        return $result;
    }

    /**
     * Verify solutions against a stored challenge and issue a verification token.
     *
     * @param int[] $solutions
     * @return array{success: bool, token?: string, expires?: int, message?: string}
     */
    public function redeemChallenge(string $token, array $solutions, array $instrumentation = [], array $requestHeaders = []): array
    {
        foreach ($solutions as $s) {
            if (!is_int($s)) {
                return ['success' => false, 'message' => 'Invalid body'];
            }
        }
        if ($token === '') {
            return ['success' => false, 'message' => 'Invalid body'];
        }

        $this->lazyCleanup();

        $data = $this->config->challengeStorage->readChallenge($token);
        $this->config->challengeStorage->deleteChallenge($token);

        if ($data === null || ($data['expires'] ?? 0) < $this->nowMs()) {
            return ['success' => false, 'message' => 'Challenge invalid or expired'];
        }

        $count = $data['c'];
        $size  = $data['s'];
        $diff  = $data['d'];

        if (count($solutions) < $count) {
            return ['success' => false, 'message' => 'Invalid solution'];
        }

        for ($i = 1; $i <= $count; $i++) {
            $salt   = Prng::generate($token . $i, $size);
            $target = Prng::generate($token . $i . 'd', $diff);
            $hash   = hash('sha256', $salt . (string)$solutions[$i - 1]);
            if (!str_starts_with($hash, $target)) {
                return ['success' => false, 'message' => 'Invalid solution'];
            }
        }

        $details = [];
        if (isset($data['instrumentation'])) {
            $verified = $this->verifyInstrumentation($data['instrumentation'], $instrumentation);
            if (!$verified['valid']) {
                return ['success' => false, 'message' => 'Blocked by instrumentation', 'error' => 'Blocked by instrumentation', 'instr_error' => true, 'reason' => $verified['reason']]
                    + (isset($verified['blockedBy']) ? ['blockedBy' => $verified['blockedBy']] : []);
            }
            $details['riskFlags'] = $verified['riskFlags'];
        }
        if (isset($verified) || $requestHeaders) {
            $policy = Policy::evaluate($verified ?? [], $data['behavior'] ?? null, $requestHeaders, $this->config->behaviorReplayCheck, $data['expires'] - $this->nowMs());
            if (!$policy['valid']) {
                unset($policy['valid']);
                return ['success' => false, 'message' => 'Blocked by interaction checks', 'error' => 'Blocked by interaction checks'] + $policy;
            }
            unset($policy['valid']);
            $details = $policy;
        }

        $vertoken = $this->randomHex(15);
        $id       = $this->randomHex(8);
        $expires  = $this->nowMs() + $this->config->tokenTtlMs;
        $key      = $id . ':' . hash('sha256', $vertoken);

        $this->config->tokenStorage->storeToken($key, $expires);

        return ['success' => true, 'token' => $id . ':' . $vertoken, 'expires' => $expires] + $details;
    }

    /** Redeem an unmodified widget JSON body, including instrumentation failure markers. */
    public function redeemChallengeBody(array $body, array $requestHeaders = []): array
    {
        if (!is_string($body['token'] ?? null) || !is_array($body['solutions'] ?? null)) {
            return ['success' => false, 'message' => 'Invalid body'];
        }
        return $this->redeemChallenge($body['token'], $body['solutions'], $body, $requestHeaders);
    }

    private function verifyInstrumentation(array $meta, array $body): array
    {
        $reason = null;
        if (($body['instr_blocked'] ?? null) === true) {
            $reason = $meta['blockAutomatedBrowsers'] ? 'instr_automated_browser' : 'instr_failed';
        } elseif (is_string($body['instr_error'] ?? null)) {
            $reason = [
                'csp_blocked' => 'instr_csp_blocked', 'csp_script_blocked' => 'instr_csp_blocked',
                'natives_tampered' => 'instr_natives_tampered', 'env_failed' => 'instr_env_failed', 'script_failed' => 'instr_script_failed',
            ][$body['instr_error']] ?? 'instr_failed';
        } elseif (($body['instr_timeout'] ?? null) === true) {
            $reason = 'instr_timeout';
        } elseif (!isset($body['instr'])) {
            $reason = 'instr_missing';
        }
        return $reason !== null ? ['valid' => false, 'reason' => $reason] : Verifier::verify($meta, $body['instr'], $this->nowMs());
    }

    /**
     * Validate a verification token returned from redeemChallenge.
     * By default, the token is consumed (deleted) on successful validation.
     */
    public function validateToken(string $token, bool $keepToken = false): bool
    {
        $this->lazyCleanup();

        if ($token === '' || !str_contains($token, ':')) {
            return false;
        }
        $parts = explode(':', $token, 2);
        if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            return false;
        }
        [$id, $vertoken] = $parts;

        $key     = $id . ':' . hash('sha256', $vertoken);
        $expires = $this->config->tokenStorage->readToken($key);

        if ($expires === null || $expires <= $this->nowMs()) {
            return false;
        }

        if (!$keepToken) {
            $this->config->tokenStorage->deleteToken($key);
        }
        return true;
    }

    /**
     * Manually run cleanup of expired challenges and tokens.
     */
    public function cleanup(): void
    {
        $this->config->challengeStorage->deleteExpiredChallenges();
        $this->config->tokenStorage->deleteExpiredTokens();
        $this->lastCleanupMs = $this->nowMs();
    }

    private function lazyCleanup(): void
    {
        if ($this->config->disableAutoCleanup) {
            return;
        }
        $now = $this->nowMs();
        if ($now - $this->lastCleanupMs > self::CLEANUP_INTERVAL_MS) {
            $this->cleanup();
        }
    }

    private function nowMs(): int
    {
        return (int)(microtime(true) * 1000);
    }

    private function randomHex(int $bytes): string
    {
        return bin2hex(random_bytes($bytes));
    }
}
