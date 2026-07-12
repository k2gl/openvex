<?php

declare(strict_types=1);

namespace K2gl\OpenVex;

/**
 * The machine-readable reason why a product carries the {@see Status::NotAffected}
 * status.
 *
 * @see https://github.com/openvex/spec — "Justifications"
 */
enum Justification: string
{
    /** The vulnerable component is not included in the product. */
    case ComponentNotPresent = 'component_not_present';

    /** The component is included, but the vulnerable code is not present. */
    case VulnerableCodeNotPresent = 'vulnerable_code_not_present';

    /** The vulnerable code is present but never executed. */
    case VulnerableCodeNotInExecutePath = 'vulnerable_code_not_in_execute_path';

    /** The vulnerable code cannot be reached or controlled by an adversary. */
    case VulnerableCodeCannotBeControlledByAdversary = 'vulnerable_code_cannot_be_controlled_by_adversary';

    /** Built-in mitigations already prevent exploitation. */
    case InlineMitigationsAlreadyExist = 'inline_mitigations_already_exist';
}
