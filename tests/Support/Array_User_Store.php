<?php

declare(strict_types=1);

namespace Atlas\WordPress\Tests\Support;

use Atlas\WordPress\Atlas_Identity;
use Atlas\WordPress\Atlas_User_Store;

/**
 * An in-memory {@see Atlas_User_Store} for testing {@see \Atlas\WordPress\Atlas_Login::resolveUser()}
 * without WordPress: it records what the mapping logic asked for, so a test can
 * assert the exact decision (linked by sub, matched by email + linked, or
 * provisioned).
 */
final class Array_User_Store implements Atlas_User_Store
{
    /** @var array<string,int> atlas sub => user id */
    public array $bySub = [];

    /** @var array<string,int> email => user id */
    public array $byEmail = [];

    /** @var array<int,string> user id => role */
    public array $roles = [];

    /** @var list<array{email: string, sub: string, role: string}> provisioning log */
    public array $created = [];

    public int $nextId = 100;

    public ?int $signedIn = null;

    public function findByAtlasSub(string $sub): ?int
    {
        return $this->bySub[$sub] ?? null;
    }

    public function findByEmail(string $email): ?int
    {
        return $this->byEmail[$email] ?? null;
    }

    public function linkAtlasSub(int $userId, string $sub): void
    {
        $this->bySub[$sub] = $userId;
    }

    public function createUser(Atlas_Identity $identity, string $role): int
    {
        $id = $this->nextId++;
        $this->created[] = ['email' => (string) $identity->email, 'sub' => $identity->subject, 'role' => $role];
        $this->bySub[$identity->subject] = $id;
        if ($identity->email !== null) {
            $this->byEmail[$identity->email] = $id;
        }
        $this->roles[$id] = $role;

        return $id;
    }

    public function roleOf(int $userId): ?string
    {
        return $this->roles[$userId] ?? null;
    }

    public function signIn(int $userId, bool $remember = false): void
    {
        $this->signedIn = $userId;
    }
}
