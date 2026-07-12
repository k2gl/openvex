<?php

declare(strict_types=1);

namespace K2gl\OpenVex;

/**
 * The status of a vulnerability with respect to the products in a statement.
 *
 * @see https://github.com/openvex/spec — "Status Labels"
 */
enum Status: string
{
    /**
     * The product is not affected by the vulnerability. Requires a
     * {@see Justification} or a free-form impact statement.
     */
    case NotAffected = 'not_affected';

    /**
     * The product is affected. Requires an action statement describing the
     * remediation or mitigation.
     */
    case Affected = 'affected';

    /** A fix has been applied in the listed product versions. */
    case Fixed = 'fixed';

    /** The impact of the vulnerability is still being investigated. */
    case UnderInvestigation = 'under_investigation';
}
