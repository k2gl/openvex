<?php

declare(strict_types=1);

namespace K2gl\OpenVex\Tests;

use DateTimeImmutable;
use K2gl\OpenVex\Component;
use K2gl\OpenVex\Document;
use K2gl\OpenVex\Product;
use K2gl\OpenVex\Statement;
use K2gl\OpenVex\Status;
use K2gl\OpenVex\Subcomponent;
use K2gl\OpenVex\Vulnerability;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

/**
 * The canonicalization vectors are taken verbatim from go-vex's
 * TestCanonicalHash, the reference implementation of the algorithm.
 */
#[CoversClass(Document::class)]
#[CoversClass(Statement::class)]
#[CoversClass(Vulnerability::class)]
#[CoversClass(Product::class)]
#[CoversClass(Component::class)]
#[CoversClass(Subcomponent::class)]
#[CoversClass(Status::class)]
final class CanonicalHashTest extends TestCase
{
    private const GOLDEN = '8ed99017785c3b43219018c7c50353c031cdaaf1c7efc146c683b0ce57123cf6';

    public function testHashesTheReferenceDocument(): void
    {
        // act
        $hash = $this->referenceDocument()->canonicalHash();

        // assert
        fact($hash)->is(self::GOLDEN);
    }

    public function testDerivesTheCanonicalIriFromTheHash(): void
    {
        // act
        $id = $this->referenceDocument()->generateId();

        // assert
        fact($id)->is('https://openvex.dev/docs/public/vex-' . self::GOLDEN);
    }

    public function testAddingAStatementChangesTheHash(): void
    {
        // arrange
        $document = new Document(
            author: 'John Doe',
            timestamp: new DateTimeImmutable('2022-12-22T16:36:43-05:00'),
            statements: [
                ...$this->referenceDocument()->statements,
                new Statement(
                    vulnerability: Vulnerability::of('CVE-2010-543231'),
                    status: Status::Affected,
                    products: [new Product(id: 'pkg:apk/wolfi/git@2.0.0')],
                    // action_statement is required by the spec but excluded from the hash
                    actionStatement: 'upgrade',
                ),
            ],
        );

        // act
        $hash = $document->canonicalHash();

        // assert
        fact($hash)->is('cbfbba00d118572164b5b934e3ced71c1b02e171f942abfe66d42775dba703cf');
    }

    public function testMetadataDoesNotAffectTheHash(): void
    {
        // arrange
        $document = new Document(
            author: 'John Doe',
            timestamp: new DateTimeImmutable('2022-12-22T16:36:43-05:00'),
            statements: $this->referenceDocument()->statements,
            id: '298347',
            role: 'abc',
            tooling: 'Fake Tool 1.0',
            supplier: 'Mr Supplier',
        );

        // act
        $hash = $document->canonicalHash();

        // assert
        fact($hash)->is(self::GOLDEN);
    }

    public function testChangingTheProductChangesTheHash(): void
    {
        // arrange
        $document = new Document(
            author: 'John Doe',
            timestamp: new DateTimeImmutable('2022-12-22T16:36:43-05:00'),
            statements: [
                new Statement(
                    vulnerability: new Vulnerability(name: 'CVE-1234-5678', aliases: ['some vulnerability alias']),
                    status: Status::UnderInvestigation,
                    products: [new Product(
                        id: 'cool router, bro',
                        subcomponents: [new Subcomponent(id: 'pkg:apk/wolfi/bash@1.0.0')],
                    )],
                ),
            ],
        );

        // act
        $hash = $document->canonicalHash();

        // assert
        fact($hash)->is('010aaeb3d6bf69c486e199a48ec40038ca347d2603142dd48d97937d8477fe37');
    }

    public function testChangingTheDocumentTimestampChangesTheHash(): void
    {
        // arrange
        $document = new Document(
            author: 'John Doe',
            timestamp: new DateTimeImmutable('2019-01-22T16:36:43-05:00'),
            statements: $this->referenceDocument()->statements,
        );

        // act
        $hash = $document->canonicalHash();

        // assert
        fact($hash)->is('d585979c1cc06797d2486382b3fd5e95d3a9b416525c95c9fefcef9863a595c8');
    }

    public function testAStatementTimestampEqualToTheDocumentDoesNotChangeTheHash(): void
    {
        // arrange
        $document = new Document(
            author: 'John Doe',
            timestamp: new DateTimeImmutable('2022-12-22T16:36:43-05:00'),
            statements: [
                new Statement(
                    vulnerability: new Vulnerability(name: 'CVE-1234-5678', aliases: ['some vulnerability alias']),
                    status: Status::UnderInvestigation,
                    products: [new Product(
                        id: 'pkg:oci/example@sha256:47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c',
                        subcomponents: [new Subcomponent(id: 'pkg:apk/wolfi/bash@1.0.0')],
                    )],
                    timestamp: new DateTimeImmutable('2022-12-22T16:36:43-05:00'),
                ),
            ],
        );

        // act
        $hash = $document->canonicalHash();

        // assert
        fact($hash)->is(self::GOLDEN);
    }

    private function referenceDocument(): Document
    {
        return new Document(
            author: 'John Doe',
            timestamp: new DateTimeImmutable('2022-12-22T16:36:43-05:00'),
            version: 1,
            role: 'VEX Writer Extraordinaire',
            tooling: 'OpenVEX',
            supplier: 'Chainguard Inc',
            statements: [
                new Statement(
                    vulnerability: new Vulnerability(name: 'CVE-1234-5678', aliases: ['some vulnerability alias']),
                    status: Status::UnderInvestigation,
                    products: [new Product(
                        id: 'pkg:oci/example@sha256:47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c',
                        subcomponents: [new Subcomponent(id: 'pkg:apk/wolfi/bash@1.0.0')],
                    )],
                ),
            ],
        );
    }
}
