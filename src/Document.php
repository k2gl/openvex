<?php

declare(strict_types=1);

namespace K2gl\OpenVex;

use DateTimeImmutable;
use JsonException;
use K2gl\OpenVex\Exception\InvalidDocumentException;

/**
 * An OpenVEX document: a set of statements about the exploitability of
 * vulnerabilities in a set of products, issued by an author at a point in time.
 *
 * @see https://github.com/openvex/spec
 */
final class Document
{
    use DecodesJson;

    public const SPEC_VERSION = '0.2.0';

    public const CONTEXT = 'https://openvex.dev/ns/v' . self::SPEC_VERSION;

    /** The namespace used to build canonical document IRIs. */
    public const PUBLIC_NAMESPACE = 'https://openvex.dev/docs';

    /**
     * @param array<Statement> $statements
     */
    public function __construct(
        public readonly string $author,
        public readonly DateTimeImmutable $timestamp,
        public readonly array $statements,
        public readonly int $version = 1,
        public readonly string $id = '',
        public readonly string $context = self::CONTEXT,
        public readonly string $role = '',
        public readonly ?DateTimeImmutable $lastUpdated = null,
        public readonly string $tooling = '',
        public readonly string $supplier = '',
    ) {}

    /**
     * @throws InvalidDocumentException
     */
    public static function fromJson(string $json): self
    {
        try {
            /** @var array<string, mixed> $data */
            $data = json_decode(
                json: $json,
                associative: true,
                flags: JSON_THROW_ON_ERROR,
            );
        } catch (JsonException $e) {
            throw new InvalidDocumentException(
                message: sprintf('Malformed OpenVEX JSON: %s', $e->getMessage()),
                previous: $e,
            );
        }

        return self::fromArray($data);
    }

    /**
     * @param array<string, mixed> $data
     *
     * @throws InvalidDocumentException
     */
    public static function fromArray(array $data): self
    {
        if (! isset($data['timestamp']) || $data['timestamp'] === '') {
            throw new InvalidDocumentException('An OpenVEX document requires a timestamp.');
        }

        $statements = [];

        foreach (self::readObject($data['statements'] ?? []) as $statement) {
            $statements[] = Statement::fromArray(self::readObject($statement));
        }

        $lastUpdatedValue = self::readString($data, 'last_updated');
        $lastUpdated = $lastUpdatedValue !== '' ? Timestamp::parse($lastUpdatedValue) : null;

        $context = self::readString($data, '@context');

        return new self(
            author: self::readString($data, 'author'),
            timestamp: Timestamp::parse(self::readString($data, 'timestamp')),
            statements: $statements,
            version: self::readInt($data, 'version', 1),
            id: self::readString($data, '@id'),
            context: $context !== '' ? $context : self::CONTEXT,
            role: self::readString($data, 'role'),
            lastUpdated: $lastUpdated,
            tooling: self::readString($data, 'tooling'),
            supplier: self::readString($data, 'supplier'),
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $out = [
            '@context' => $this->context,
            '@id' => $this->id !== '' ? $this->id : $this->generateId(),
            'author' => $this->author,
        ];

        if ($this->role !== '') {
            $out['role'] = $this->role;
        }

        $out['timestamp'] = Timestamp::format($this->timestamp);

        if ($this->lastUpdated instanceof DateTimeImmutable) {
            $out['last_updated'] = Timestamp::format($this->lastUpdated);
        }

        $out['version'] = $this->version;

        if ($this->tooling !== '') {
            $out['tooling'] = $this->tooling;
        }

        if ($this->supplier !== '') {
            $out['supplier'] = $this->supplier;
        }

        $out['statements'] = array_map(
            static fn (Statement $statement): array => $statement->toArray(),
            $this->statements,
        );

        return $out;
    }

    public function toJson(int $flags = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE): string
    {
        return json_encode($this->toArray(), $flags | JSON_THROW_ON_ERROR);
    }

    /**
     * The SHA-256 canonicalization hash of the document's impact statements.
     * It is stable across changes to metadata and only reflects the statements
     * themselves, matching go-vex's CanonicalHash.
     */
    public function canonicalHash(): string
    {
        $cString = (string) $this->timestamp->getTimestamp();
        $cString .= ':' . $this->version;
        $cString .= ':' . $this->author;

        foreach ($this->sortedStatements() as $statement) {
            $justification = $statement->justification !== null ? $statement->justification->value : '';

            $cString .= $statement->vulnerability->canonicalFragment();
            $cString .= ':' . $statement->status->value . ':' . $justification;
            $cString .= ':' . $statement->effectiveTimestamp($this->timestamp)->getTimestamp();

            $products = [];

            foreach ($statement->products as $product) {
                $products[] = $product->canonicalFragment();
            }

            sort($products);

            $cString .= implode(':', $products);
        }

        return hash('sha256', $cString);
    }

    /**
     * The canonical IRI for the document, derived from {@see canonicalHash}.
     */
    public function generateId(): string
    {
        if ($this->id !== '') {
            return $this->id;
        }

        return sprintf('%s/public/vex-%s', self::PUBLIC_NAMESPACE, $this->canonicalHash());
    }

    /**
     * Returns a copy of the document with its {@see id} set to the canonical IRI.
     */
    public function withCanonicalId(): self
    {
        if ($this->id !== '') {
            return $this;
        }

        return new self(
            author: $this->author,
            timestamp: $this->timestamp,
            statements: $this->statements,
            version: $this->version,
            id: $this->generateId(),
            context: $this->context,
            role: $this->role,
            lastUpdated: $this->lastUpdated,
            tooling: $this->tooling,
            supplier: $this->supplier,
        );
    }

    /**
     * The statements whose products (or their subcomponents) match the given
     * IRI, purl, CPE or hash digest.
     *
     * @return array<Statement>
     */
    public function statementsFor(string $identifier): array
    {
        return array_values(array_filter(
            $this->statements,
            static function (Statement $statement) use ($identifier): bool {
                foreach ($statement->products as $product) {
                    if ($product->matchesIdentifier($identifier)) {
                        return true;
                    }
                }

                return false;
            },
        ));
    }

    /**
     * @return array<Statement>
     */
    private function sortedStatements(): array
    {
        $statements = $this->statements;

        usort(
            $statements,
            function (Statement $a, Statement $b): int {
                $byVulnerability = strcmp($a->vulnerability->name, $b->vulnerability->name);

                if ($byVulnerability !== 0) {
                    return $byVulnerability;
                }

                return $a->effectiveTimestamp($this->timestamp)->getTimestamp()
                    <=> $b->effectiveTimestamp($this->timestamp)->getTimestamp();
            },
        );

        return $statements;
    }
}
