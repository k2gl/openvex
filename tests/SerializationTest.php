<?php

declare(strict_types=1);

namespace K2gl\OpenVex\Tests;

use K2gl\OpenVex\Component;
use K2gl\OpenVex\Document;
use K2gl\OpenVex\Exception\InvalidDocumentException;
use K2gl\OpenVex\Justification;
use K2gl\OpenVex\Product;
use K2gl\OpenVex\Statement;
use K2gl\OpenVex\Status;
use K2gl\OpenVex\Subcomponent;
use K2gl\OpenVex\Timestamp;
use K2gl\OpenVex\Vulnerability;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(Document::class)]
#[CoversClass(Statement::class)]
#[CoversClass(Vulnerability::class)]
#[CoversClass(Product::class)]
#[CoversClass(Component::class)]
#[CoversClass(Subcomponent::class)]
#[CoversClass(Status::class)]
#[CoversClass(Justification::class)]
#[CoversClass(Timestamp::class)]
final class SerializationTest extends TestCase
{
    public function testParsesTheDocumentMetadata(): void
    {
        // act
        $document = Document::fromJson($this->fixture());

        // assert
        fact($document->author)->is('The OpenVEX Project <openvex@openssf.org>');
        fact($document->version)->is(1);
        fact($document->context)->is('https://openvex.dev/ns/v0.2.0');
        fact($document->statements)->count(5);
    }

    public function testParsesAProductWithSubcomponents(): void
    {
        // arrange
        $document = Document::fromJson($this->fixture());

        // act
        $statement = $document->statements[0];
        $product = $statement->products[0];

        // assert
        fact($statement->vulnerability->name)->is('CVE-2023-1255');
        fact($statement->status)->is(Status::Fixed);
        fact($product->id)->startsWith('pkg:oci/alpine@sha256');
        fact($product->subcomponents)->count(2);
    }

    public function testParsesANotAffectedStatementWithJustification(): void
    {
        // arrange
        $document = Document::fromJson($this->fixture());

        // act — CVE-2023-3446 is the first not_affected statement
        $statement = $document->statementsFor(
            'pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126',
        )[3];

        // assert
        fact($statement->status)->is(Status::NotAffected);
        fact($statement->justification)->is(Justification::VulnerableCodeNotPresent);
        fact($statement->impactStatement)->is('affected functions were removed before packaging');
    }

    public function testRoundTripsWithoutLosingStatements(): void
    {
        // arrange
        $document = Document::fromJson($this->fixture());

        // act
        $reparsed = Document::fromJson($document->toJson());

        // assert
        fact($reparsed->statements)->count(5);
        fact($reparsed->canonicalHash())->is($document->canonicalHash());
    }

    public function testEmitsWellFormedJson(): void
    {
        // arrange
        $document = Document::fromJson($this->fixture());

        // act
        $json = $document->toJson();

        // assert
        fact(json_decode($json, true))->isArray();
        fact($json)->containsString('"@context"');
    }

    public function testRejectsMalformedJson(): void
    {
        // assert
        fact(static fn () => Document::fromJson('{not json'))
            ->throws(InvalidDocumentException::class, 'Malformed');
    }

    public function testRejectsADocumentWithoutATimestamp(): void
    {
        // assert
        fact(static fn () => Document::fromArray(['author' => 'x', 'statements' => []]))
            ->throws(InvalidDocumentException::class, 'requires a timestamp');
    }

    private function fixture(): string
    {
        return (string) file_get_contents(__DIR__ . '/fixtures/openvex-v0.2.0.json');
    }
}
