<?php

declare(strict_types=1);

namespace K2gl\OpenVex;

/**
 * A component of a {@see Product} that is related to the statement's
 * vulnerability. Unlike a product, a subcomponent cannot nest further
 * components.
 */
final class Subcomponent extends Component
{
    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $base = parent::fromArray($data);

        return new self(
            id: $base->id,
            hashes: $base->hashes,
            identifiers: $base->identifiers,
            supplier: $base->supplier,
        );
    }
}
