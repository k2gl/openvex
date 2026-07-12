<?php

declare(strict_types=1);

namespace K2gl\OpenVex;

/**
 * Type-safe readers for the loosely-typed arrays produced by json_decode.
 *
 * @internal
 */
trait DecodesJson
{
    /**
     * @param array<string, mixed> $data
     */
    protected static function readString(array $data, string $key): string
    {
        $value = $data[$key] ?? '';

        if (is_string($value)) {
            return $value;
        }

        return is_scalar($value) ? (string) $value : '';
    }

    /**
     * @param array<string, mixed> $data
     */
    protected static function readInt(array $data, string $key, int $default): int
    {
        $value = $data[$key] ?? $default;

        if (is_int($value)) {
            return $value;
        }

        return is_numeric($value) ? (int) $value : $default;
    }

    /**
     * Normalizes a decoded JSON value into a string-keyed object array.
     *
     * @return array<string, mixed>
     */
    protected static function readObject(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        $out = [];

        foreach ($value as $key => $item) {
            $out[(string) $key] = $item;
        }

        return $out;
    }

    /**
     * @return array<string>
     */
    protected static function readStringList(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        $out = [];

        foreach ($value as $item) {
            if (is_scalar($item)) {
                $out[] = (string) $item;
            }
        }

        return $out;
    }

    /**
     * @return array<string, string>
     */
    protected static function readStringMap(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        $out = [];

        foreach ($value as $key => $item) {
            if (is_scalar($item)) {
                $out[(string) $key] = (string) $item;
            }
        }

        return $out;
    }
}
