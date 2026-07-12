<?php

declare(strict_types=1);

namespace K2gl\OpenVex;

/**
 * A piece of software identified by an IRI, cryptographic hashes and/or
 * software identifiers (purl, CPE). Shared by {@see Product} and
 * {@see Subcomponent}.
 *
 * @see https://github.com/openvex/spec — "Product" / "Subcomponent"
 */
class Component
{
    use DecodesJson;

    /**
     * @param string                $id          an IRI or purl identifying the component
     * @param array<string, string> $hashes      map of algorithm (e.g. "sha-256") to hex digest
     * @param array<string, string> $identifiers map of identifier type ("purl", "cpe22", "cpe23") to value
     * @param string                $supplier    an optional supplier identifier
     */
    public function __construct(
        public readonly string $id = '',
        public readonly array $hashes = [],
        public readonly array $identifiers = [],
        public readonly string $supplier = '',
    ) {}

    public static function of(string $id): self
    {
        return new self(id: $id);
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            id: self::readString($data, '@id'),
            hashes: self::readStringMap($data['hashes'] ?? []),
            identifiers: self::readStringMap($data['identifiers'] ?? []),
            supplier: self::readString($data, 'supplier'),
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $out = [];

        if ($this->id !== '') {
            $out['@id'] = $this->id;
        }

        if ($this->hashes !== []) {
            $out['hashes'] = $this->hashes;
        }

        if ($this->identifiers !== []) {
            $out['identifiers'] = $this->identifiers;
        }

        if ($this->supplier !== '') {
            $out['supplier'] = $this->supplier;
        }

        return $out;
    }

    /**
     * The canonicalization fragment for this component, matching go-vex's
     * cstringFromComponent. Map keys are sorted so the output is deterministic
     * regardless of insertion order (go-vex leaves this to Go's random map
     * iteration; sorting is a faithful superset for single-entry maps and a
     * strict improvement otherwise).
     */
    public function canonicalFragment(): string
    {
        $fragment = ':' . $this->id;

        $hashes = $this->hashes;
        ksort($hashes);

        foreach ($hashes as $algorithm => $value) {
            $fragment .= ':' . $algorithm . '@' . $value;
        }

        $identifiers = $this->identifiers;
        ksort($identifiers);

        foreach ($identifiers as $type => $value) {
            $fragment .= ':' . $type . '@' . $value;
        }

        return $fragment;
    }

    /**
     * Whether the given IRI, purl, CPE or hash digest identifies this component.
     */
    public function matchesIdentifier(string $identifier): bool
    {
        if ($identifier === '') {
            return false;
        }

        if ($this->id === $identifier) {
            return true;
        }

        return in_array($identifier, $this->identifiers, true)
            || in_array($identifier, $this->hashes, true);
    }
}
