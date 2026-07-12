<?php

declare(strict_types=1);

namespace K2gl\OpenVex\Tests;

use K2gl\OpenVex\Exception\InvalidStatementException;
use K2gl\OpenVex\Justification;
use K2gl\OpenVex\Statement;
use K2gl\OpenVex\Status;
use K2gl\OpenVex\Vulnerability;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(Statement::class)]
#[CoversClass(Vulnerability::class)]
final class StatementTest extends TestCase
{
    public function testAcceptsNotAffectedWithAJustification(): void
    {
        // act
        $statement = new Statement(
            vulnerability: Vulnerability::of('CVE-2024-1'),
            status: Status::NotAffected,
            justification: Justification::VulnerableCodeNotPresent,
        );

        // assert
        fact($statement->status)->is(Status::NotAffected);
        fact($statement->justification)->is(Justification::VulnerableCodeNotPresent);
    }

    public function testAcceptsNotAffectedWithOnlyAnImpactStatement(): void
    {
        // act
        $statement = new Statement(
            vulnerability: Vulnerability::of('CVE-2024-2'),
            status: Status::NotAffected,
            impactStatement: 'the affected function was removed before packaging',
        );

        // assert
        fact($statement->impactStatement)->is('the affected function was removed before packaging');
    }

    public function testAcceptsAffectedWithAnActionStatement(): void
    {
        // act
        $statement = new Statement(
            vulnerability: Vulnerability::of('CVE-2024-3'),
            status: Status::Affected,
            actionStatement: 'upgrade to 1.2.3',
        );

        // assert
        fact($statement->actionStatement)->is('upgrade to 1.2.3');
    }

    public function testAcceptsFixedWithoutFurtherFields(): void
    {
        // act
        $statement = new Statement(
            vulnerability: Vulnerability::of('CVE-2024-4'),
            status: Status::Fixed,
        );

        // assert
        fact($statement->status)->is(Status::Fixed);
    }

    public function testRejectsNotAffectedWithoutJustificationOrImpact(): void
    {
        // assert
        fact(static fn () => new Statement(
            vulnerability: Vulnerability::of('CVE-2024-5'),
            status: Status::NotAffected,
        ))->throws(InvalidStatementException::class, 'justification or an impact_statement');
    }

    public function testRejectsNotAffectedCarryingAnActionStatement(): void
    {
        // assert
        fact(static fn () => new Statement(
            vulnerability: Vulnerability::of('CVE-2024-6'),
            status: Status::NotAffected,
            justification: Justification::ComponentNotPresent,
            actionStatement: 'should not be here',
        ))->throws(InvalidStatementException::class, 'must not carry an action_statement');
    }

    public function testRejectsAffectedWithoutAnActionStatement(): void
    {
        // assert
        fact(static fn () => new Statement(
            vulnerability: Vulnerability::of('CVE-2024-7'),
            status: Status::Affected,
        ))->throws(InvalidStatementException::class, 'requires an action_statement');
    }

    public function testRejectsFixedCarryingAJustification(): void
    {
        // assert
        fact(static fn () => new Statement(
            vulnerability: Vulnerability::of('CVE-2024-8'),
            status: Status::Fixed,
            justification: Justification::ComponentNotPresent,
        ))->throws(InvalidStatementException::class, 'must not carry a justification');
    }
}
