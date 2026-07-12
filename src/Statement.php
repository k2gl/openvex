<?php

declare(strict_types=1);

namespace K2gl\OpenVex;

use DateTimeImmutable;
use K2gl\OpenVex\Exception\InvalidStatementException;

/**
 * A single claim about the status of a vulnerability in one or more products.
 *
 * The status rules of the spec are enforced on construction, so a Statement
 * instance is always valid.
 *
 * @see https://github.com/openvex/spec — "The VEX statement"
 */
final class Statement
{
    use DecodesJson;

    /**
     * @param array<Product> $products
     */
    public function __construct(
        public readonly Vulnerability $vulnerability,
        public readonly Status $status,
        public readonly array $products = [],
        public readonly ?Justification $justification = null,
        public readonly string $impactStatement = '',
        public readonly string $actionStatement = '',
        public readonly string $statusNotes = '',
        public readonly string $id = '',
        public readonly ?DateTimeImmutable $timestamp = null,
        public readonly ?DateTimeImmutable $lastUpdated = null,
        public readonly ?DateTimeImmutable $actionStatementTimestamp = null,
    ) {
        $this->assertConsistent();
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $products = [];

        foreach (self::readObject($data['products'] ?? []) as $product) {
            $products[] = Product::fromArray(self::readObject($product));
        }

        $justificationValue = self::readString($data, 'justification');
        $justification = $justificationValue !== '' ? Justification::from($justificationValue) : null;

        return new self(
            vulnerability: Vulnerability::fromArray(self::readObject($data['vulnerability'] ?? [])),
            status: Status::from(self::readString($data, 'status')),
            products: $products,
            justification: $justification,
            impactStatement: self::readString($data, 'impact_statement'),
            actionStatement: self::readString($data, 'action_statement'),
            statusNotes: self::readString($data, 'status_notes'),
            id: self::readString($data, '@id'),
            timestamp: self::readTime($data, 'timestamp'),
            lastUpdated: self::readTime($data, 'last_updated'),
            actionStatementTimestamp: self::readTime($data, 'action_statement_timestamp'),
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

        $out['vulnerability'] = $this->vulnerability->toArray();

        if ($this->timestamp instanceof DateTimeImmutable) {
            $out['timestamp'] = Timestamp::format($this->timestamp);
        }

        if ($this->lastUpdated instanceof DateTimeImmutable) {
            $out['last_updated'] = Timestamp::format($this->lastUpdated);
        }

        if ($this->products !== []) {
            $out['products'] = array_map(
                static fn (Product $product): array => $product->toArray(),
                $this->products,
            );
        }

        $out['status'] = $this->status->value;

        if ($this->statusNotes !== '') {
            $out['status_notes'] = $this->statusNotes;
        }

        if ($this->justification instanceof Justification) {
            $out['justification'] = $this->justification->value;
        }

        if ($this->impactStatement !== '') {
            $out['impact_statement'] = $this->impactStatement;
        }

        if ($this->actionStatement !== '') {
            $out['action_statement'] = $this->actionStatement;
        }

        if ($this->actionStatementTimestamp instanceof DateTimeImmutable) {
            $out['action_statement_timestamp'] = Timestamp::format($this->actionStatementTimestamp);
        }

        return $out;
    }

    /**
     * The effective timestamp of the statement, falling back to the document's
     * timestamp when the statement does not carry its own.
     */
    public function effectiveTimestamp(DateTimeImmutable $documentTimestamp): DateTimeImmutable
    {
        return $this->timestamp ?? $documentTimestamp;
    }

    private function assertConsistent(): void
    {
        switch ($this->status) {
            case Status::NotAffected:
                if ($this->justification === null && $this->impactStatement === '') {
                    throw new InvalidStatementException(
                        'A "not_affected" statement requires a justification or an impact_statement.',
                    );
                }

                if ($this->actionStatement !== '') {
                    throw new InvalidStatementException(
                        'A "not_affected" statement must not carry an action_statement.',
                    );
                }

                break;

            case Status::Affected:
                if ($this->actionStatement === '') {
                    throw new InvalidStatementException(
                        'An "affected" statement requires an action_statement.',
                    );
                }

                $this->assertNoImpactOrJustification('affected');

                break;

            case Status::Fixed:
            case Status::UnderInvestigation:
                if ($this->actionStatement !== '') {
                    throw new InvalidStatementException(
                        sprintf('A "%s" statement must not carry an action_statement.', $this->status->value),
                    );
                }

                $this->assertNoImpactOrJustification($this->status->value);

                break;
        }
    }

    private function assertNoImpactOrJustification(string $status): void
    {
        if ($this->justification !== null) {
            throw new InvalidStatementException(
                sprintf('A "%s" statement must not carry a justification.', $status),
            );
        }

        if ($this->impactStatement !== '') {
            throw new InvalidStatementException(
                sprintf('A "%s" statement must not carry an impact_statement.', $status),
            );
        }
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function readTime(array $data, string $key): ?DateTimeImmutable
    {
        $value = self::readString($data, $key);

        if ($value === '') {
            return null;
        }

        return Timestamp::parse($value);
    }
}
