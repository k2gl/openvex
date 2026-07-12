<?php

declare(strict_types=1);

namespace K2gl\OpenVex;

use DateTimeImmutable;
use Exception;
use K2gl\OpenVex\Exception\InvalidDocumentException;

/**
 * Parses and formats the RFC 3339 timestamps used by OpenVEX. Fractional
 * seconds finer than microseconds (PHP's limit) are truncated on parse; the
 * canonical hash only ever uses whole seconds, so this never affects a
 * document's identity.
 *
 * @internal
 */
final class Timestamp
{
    public static function parse(string $value): DateTimeImmutable
    {
        // Trim any sub-microsecond fractional digits (e.g. Go's nanoseconds)
        // down to six so DateTimeImmutable can parse the value.
        $normalized = preg_replace(
            '/(\.\d{6})\d+/',
            '$1',
            $value,
        );

        try {
            return new DateTimeImmutable((string) $normalized);
        } catch (Exception $e) {
            throw new InvalidDocumentException(
                message: sprintf('Invalid RFC 3339 timestamp: "%s".', $value),
                previous: $e,
            );
        }
    }

    public static function format(DateTimeImmutable $value): string
    {
        $microseconds = (int) $value->format('u');

        if ($microseconds === 0) {
            return $value->format('Y-m-d\TH:i:sP');
        }

        return $value->format('Y-m-d\TH:i:s.uP');
    }
}
