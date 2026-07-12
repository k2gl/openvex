<?php

declare(strict_types=1);

namespace K2gl\OpenVex;

use DateTimeImmutable;

/**
 * Fluent entry point for authoring OpenVEX documents.
 *
 * <code>
 * $json = OpenVex::create(author: 'Acme, Inc.')
 *     ->statement(
 *         vulnerability: 'CVE-2024-1234',
 *         status: Status::NotAffected,
 *         products: ['pkg:composer/k2gl/dsse@1.3.0'],
 *         justification: Justification::VulnerableCodeNotInExecutePath,
 *     )
 *     ->toJson();
 * </code>
 */
final class OpenVex
{
    /** @var array<Statement> */
    private array $statements = [];

    private function __construct(
        private readonly string $author,
        private readonly DateTimeImmutable $timestamp,
        private readonly int $version,
        private readonly string $role,
        private readonly string $tooling,
        private readonly string $supplier,
    ) {}

    public static function create(
        string $author,
        ?DateTimeImmutable $timestamp = null,
        int $version = 1,
        string $role = '',
        string $tooling = '',
        string $supplier = '',
    ): self {
        return new self(
            author: $author,
            timestamp: $timestamp ?? new DateTimeImmutable('now'),
            version: $version,
            role: $role,
            tooling: $tooling,
            supplier: $supplier,
        );
    }

    /**
     * @param string|Vulnerability          $vulnerability a CVE id (or other identifier) or a full object
     * @param array<string|Product>         $products      product IRIs/purls or full {@see Product} objects
     */
    public function statement(
        string|Vulnerability $vulnerability,
        Status $status,
        array $products = [],
        ?Justification $justification = null,
        string $impactStatement = '',
        string $actionStatement = '',
        string $statusNotes = '',
    ): self {
        $this->statements[] = new Statement(
            vulnerability: is_string($vulnerability) ? Vulnerability::of($vulnerability) : $vulnerability,
            status: $status,
            products: array_map(
                static fn (string|Product $product): Product => is_string($product) ? Product::of($product) : $product,
                $products,
            ),
            justification: $justification,
            impactStatement: $impactStatement,
            actionStatement: $actionStatement,
            statusNotes: $statusNotes,
        );

        return $this;
    }

    /**
     * Builds the document with its canonical {@see Document::generateId} IRI set.
     */
    public function build(): Document
    {
        $document = new Document(
            author: $this->author,
            timestamp: $this->timestamp,
            statements: $this->statements,
            version: $this->version,
            role: $this->role,
            tooling: $this->tooling,
            supplier: $this->supplier,
        );

        return $document->withCanonicalId();
    }

    public function toJson(int $flags = JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE): string
    {
        return $this->build()->toJson($flags);
    }
}
