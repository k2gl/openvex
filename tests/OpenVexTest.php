<?php

declare(strict_types=1);

namespace K2gl\OpenVex\Tests;

use DateTimeImmutable;
use K2gl\OpenVex\Component;
use K2gl\OpenVex\Document;
use K2gl\OpenVex\Justification;
use K2gl\OpenVex\OpenVex;
use K2gl\OpenVex\Product;
use K2gl\OpenVex\Statement;
use K2gl\OpenVex\Status;
use K2gl\OpenVex\Timestamp;
use K2gl\OpenVex\Vulnerability;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(OpenVex::class)]
#[CoversClass(Document::class)]
#[CoversClass(Statement::class)]
#[CoversClass(Vulnerability::class)]
#[CoversClass(Product::class)]
#[CoversClass(Component::class)]
#[CoversClass(Status::class)]
#[CoversClass(Justification::class)]
#[CoversClass(Timestamp::class)]
final class OpenVexTest extends TestCase
{
    public function testBuildsADocumentFromStringShorthands(): void
    {
        // act
        $document = OpenVex::create(
            author: 'Acme, Inc.',
            timestamp: new DateTimeImmutable('2024-01-01T00:00:00+00:00'),
        )->statement(
            vulnerability: 'CVE-2024-1234',
            status: Status::NotAffected,
            products: ['pkg:composer/k2gl/dsse@1.3.0'],
            justification: Justification::VulnerableCodeNotInExecutePath,
        )->build();

        // assert
        fact($document->author)->is('Acme, Inc.');
        fact($document->statements)->count(1);

        // assert: the string shorthands were promoted to value objects
        $statement = $document->statements[0];
        fact($statement->vulnerability->name)->is('CVE-2024-1234');
        fact($statement->products[0]->id)->is('pkg:composer/k2gl/dsse@1.3.0');
        fact($statement->justification)->is(Justification::VulnerableCodeNotInExecutePath);
    }

    public function testStampsTheCanonicalIdOnBuild(): void
    {
        // arrange
        $builder = OpenVex::create(
            author: 'Acme, Inc.',
            timestamp: new DateTimeImmutable('2024-01-01T00:00:00+00:00'),
        )->statement(
            vulnerability: 'CVE-2024-1234',
            status: Status::Fixed,
            products: ['pkg:composer/k2gl/dsse@1.3.0'],
        );

        // act
        $document = $builder->build();

        // assert
        fact($document->id)->startsWith('https://openvex.dev/docs/public/vex-');
    }

    public function testSerializesDirectlyToJson(): void
    {
        // act
        $json = OpenVex::create(
            author: 'Acme, Inc.',
            timestamp: new DateTimeImmutable('2024-01-01T00:00:00+00:00'),
        )->statement(
            vulnerability: 'CVE-2024-1234',
            status: Status::UnderInvestigation,
            products: ['pkg:composer/k2gl/dsse@1.3.0'],
        )->toJson();

        // assert
        fact(json_decode($json, true))->isArray();
        fact($json)->containsString('under_investigation');
    }
}
