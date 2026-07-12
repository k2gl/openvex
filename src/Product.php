<?php

declare(strict_types=1);

namespace K2gl\OpenVex;

/**
 * The piece of software a statement makes a claim about. A product may list
 * the {@see Subcomponent}s that carry the vulnerability.
 *
 * @see https://github.com/openvex/spec — "Product"
 */
final class Product extends Component
{
    /** @var array<Subcomponent> */
    public readonly array $subcomponents;

    /**
     * @param string                $id            an IRI or purl identifying the product
     * @param array<Subcomponent>   $subcomponents the affected subcomponents, if any
     * @param array<string, string> $hashes        map of algorithm to hex digest
     * @param array<string, string> $identifiers   map of identifier type to value
     * @param string                $supplier      an optional supplier identifier
     */
    public function __construct(
        string $id = '',
        array $subcomponents = [],
        array $hashes = [],
        array $identifiers = [],
        string $supplier = '',
    ) {
        parent::__construct(
            id: $id,
            hashes: $hashes,
            identifiers: $identifiers,
            supplier: $supplier,
        );

        $this->subcomponents = array_values($subcomponents);
    }

    public static function of(string $id): self
    {
        return new self(id: $id);
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $base = parent::fromArray($data);

        $subcomponents = [];

        foreach (self::readObject($data['subcomponents'] ?? []) as $sub) {
            $subcomponents[] = Subcomponent::fromArray(self::readObject($sub));
        }

        return new self(
            id: $base->id,
            subcomponents: $subcomponents,
            hashes: $base->hashes,
            identifiers: $base->identifiers,
            supplier: $base->supplier,
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $out = parent::toArray();

        if ($this->subcomponents !== []) {
            $out['subcomponents'] = array_map(
                static fn (Subcomponent $sub): array => $sub->toArray(),
                $this->subcomponents,
            );
        }

        return $out;
    }

    public function canonicalFragment(): string
    {
        $fragment = parent::canonicalFragment();

        foreach ($this->subcomponents as $subcomponent) {
            $fragment .= $subcomponent->canonicalFragment();
        }

        return $fragment;
    }

    /**
     * Whether the identifier matches the product itself or one of its
     * subcomponents.
     */
    public function matchesIdentifier(string $identifier): bool
    {
        if (parent::matchesIdentifier($identifier)) {
            return true;
        }

        foreach ($this->subcomponents as $subcomponent) {
            if ($subcomponent->matchesIdentifier($identifier)) {
                return true;
            }
        }

        return false;
    }
}
