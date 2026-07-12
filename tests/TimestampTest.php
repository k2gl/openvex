<?php

declare(strict_types=1);

namespace K2gl\OpenVex\Tests;

use K2gl\OpenVex\Exception\InvalidDocumentException;
use K2gl\OpenVex\Timestamp;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

use function K2gl\PHPUnitFluentAssertions\fact;

#[CoversClass(Timestamp::class)]
final class TimestampTest extends TestCase
{
    public function testParsesAnRfc3339Timestamp(): void
    {
        // act
        $timestamp = Timestamp::parse('2024-01-02T03:04:05+00:00');

        // assert
        fact($timestamp->format('Y-m-d H:i:s'))->is('2024-01-02 03:04:05');
    }

    public function testTruncatesSubMicrosecondPrecisionToParseNanoseconds(): void
    {
        // act — go emits nanoseconds, which PHP cannot hold
        $timestamp = Timestamp::parse('2023-07-17T18:28:47.696004345-06:00');

        // assert: the whole-second value used by the canonical hash is preserved
        fact($timestamp->getTimestamp())->is(1689640127);
    }

    public function testFormatsWithoutFractionWhenThereIsNone(): void
    {
        // arrange
        $timestamp = Timestamp::parse('2024-01-02T03:04:05+00:00');

        // act
        $formatted = Timestamp::format($timestamp);

        // assert
        fact($formatted)->is('2024-01-02T03:04:05+00:00');
    }

    public function testRejectsAnUnparseableValue(): void
    {
        // assert
        fact(static fn () => Timestamp::parse('not a date'))
            ->throws(InvalidDocumentException::class, 'Invalid RFC 3339 timestamp');
    }
}
