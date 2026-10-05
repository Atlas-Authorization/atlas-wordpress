<?php

declare(strict_types=1);

namespace Atlas\WordPress\Tests\Support;

use GuzzleHttp\Psr7\Response;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * A PSR-18 client for the tests: returns queued responses in order and records
 * every request, so a test can assert the exact method, URL and body the plugin
 * produced with no network at all. Mirrors the atlas-php `tests/Support/MockClient`.
 */
final class MockClient implements ClientInterface
{
    /** @var list<ResponseInterface|callable(RequestInterface):ResponseInterface> */
    private array $queue = [];

    /** @var list<RequestInterface> every request sent, in order */
    public array $requests = [];

    /**
     * @param array<string,mixed>|string|null $body array → JSON; string → verbatim; null → empty
     * @param array<string,string>            $headers
     */
    public function push(int $status, array|string|null $body = null, array $headers = []): void
    {
        $text = is_array($body) ? json_encode($body, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) : ($body ?? '');
        $this->queue[] = new Response($status, $headers, $text);
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests[] = $request;

        if ($this->queue === []) {
            throw new \RuntimeException('MockClient received an unexpected request: ' . $request->getUri());
        }

        $next = array_shift($this->queue);

        return $next instanceof ResponseInterface ? $next : $next($request);
    }

    public function lastRequest(): RequestInterface
    {
        if ($this->requests === []) {
            throw new \RuntimeException('No request was sent.');
        }

        return $this->requests[array_key_last($this->requests)];
    }

    public function requestCount(): int
    {
        return count($this->requests);
    }
}
