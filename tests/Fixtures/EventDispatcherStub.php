<?php

namespace OAuth2\Tests\Fixtures;

use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Minimal PSR-14 dispatcher for testing.
 *
 * It records every dispatched event and hands it to an optional listener, so tests
 * can both inspect what the server published and mutate it the way a real OIDC
 * subscriber would.
 */
class EventDispatcherStub implements EventDispatcherInterface
{
    /**
     * @var object[]
     */
    private array $dispatched = array();

    /**
     * @var null|callable
     */
    private $listener;

    public function __construct(?callable $listener = null)
    {
        $this->listener = $listener;
    }

    public function dispatch(object $event): object
    {
        $this->dispatched[] = $event;

        if ($this->listener !== null) {
            call_user_func($this->listener, $event);
        }

        return $event;
    }

    /**
     * @return object[]
     */
    public function getDispatchedEvents(): array
    {
        return $this->dispatched;
    }

    public function getLastEvent(): ?object
    {
        return $this->dispatched === array() ? null : $this->dispatched[count($this->dispatched) - 1];
    }

    public function countDispatchedEvents(): int
    {
        return count($this->dispatched);
    }
}
