<?php

declare(strict_types=1);

namespace K2gl\OpenVex\Tests;

use K2gl\OpenVex\Justification;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(Justification::class)]
final class JustificationTest extends TestCase
{
    public function testCarriesTheSpecWireValues(): void
    {
        // assert
        fact(Justification::ComponentNotPresent->value)->is('component_not_present');
        fact(Justification::VulnerableCodeNotPresent->value)->is('vulnerable_code_not_present');
        fact(Justification::VulnerableCodeNotInExecutePath->value)->is('vulnerable_code_not_in_execute_path');
        fact(Justification::VulnerableCodeCannotBeControlledByAdversary->value)
            ->is('vulnerable_code_cannot_be_controlled_by_adversary');
        fact(Justification::InlineMitigationsAlreadyExist->value)->is('inline_mitigations_already_exist');
    }

    public function testParsesFromItsWireValue(): void
    {
        // act
        $justification = Justification::from('component_not_present');

        // assert
        fact($justification)->is(Justification::ComponentNotPresent);
    }
}
