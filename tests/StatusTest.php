<?php

declare(strict_types=1);

namespace K2gl\OpenVex\Tests;

use K2gl\OpenVex\Status;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use ValueError;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(Status::class)]
final class StatusTest extends TestCase
{
    public function testCarriesTheSpecWireValues(): void
    {
        // assert
        fact(Status::NotAffected->value)->is('not_affected');
        fact(Status::Affected->value)->is('affected');
        fact(Status::Fixed->value)->is('fixed');
        fact(Status::UnderInvestigation->value)->is('under_investigation');
    }

    public function testParsesFromItsWireValue(): void
    {
        // act
        $status = Status::from('under_investigation');

        // assert
        fact($status)->is(Status::UnderInvestigation);
    }

    public function testRejectsAnUnknownWireValue(): void
    {
        // assert
        fact(static fn () => Status::from('resolved'))->throws(ValueError::class);
    }
}
