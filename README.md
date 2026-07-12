# k2gl/openvex

[![CI](https://img.shields.io/github/actions/workflow/status/k2gl/openvex/ci.yml?branch=main&label=CI&logo=github)](https://github.com/k2gl/openvex/actions/workflows/ci.yml)
[![Latest Stable Version](https://img.shields.io/packagist/v/k2gl/openvex?logo=packagist&logoColor=white)](https://packagist.org/packages/k2gl/openvex)
[![Total Downloads](https://img.shields.io/packagist/dt/k2gl/openvex?logo=packagist&logoColor=white)](https://packagist.org/packages/k2gl/openvex)
[![PHPStan Level](https://img.shields.io/badge/PHPStan-level%209-2a5ea7?logo=php&logoColor=white)](https://phpstan.org)
[![License](https://img.shields.io/packagist/l/k2gl/openvex?color=yellowgreen)](https://packagist.org/packages/k2gl/openvex)

Read, write and canonicalize [OpenVEX](https://github.com/openvex/spec) documents in PHP.

VEX (Vulnerability Exploitability eXchange) answers the question a scanner can't: a CVE
appears in your SBOM, but does it actually affect the shipped artifact? An OpenVEX document
records that judgement — `not_affected`, `affected`, `fixed` or `under_investigation`,
with a machine-readable reason — so a consumer can suppress the noise with an audit trail.

It gives you:

- **Model** — immutable value objects for the whole spec (documents, statements,
  vulnerabilities, products and subcomponents) that enforce the status/justification
  rules on construction, so an invalid statement can't exist.
- **(De)serialization** — `fromJson()` / `toJson()` round-trips real-world documents.
- **Canonical hash & IRI** — the deterministic document `@id`, byte-for-byte compatible
  with the reference implementation ([`openvex/go-vex`](https://github.com/openvex/go-vex)).

## Install

```bash
composer require k2gl/openvex
```

Requires PHP 8.1+ and `ext-json` (bundled with PHP). No other dependencies.

## Usage

### Author a document

```php
use K2gl\OpenVex\OpenVex;
use K2gl\OpenVex\Status;
use K2gl\OpenVex\Justification;

$json = OpenVex::create(author: 'Acme, Inc.')
    ->statement(
        vulnerability: 'CVE-2024-1234',
        status: Status::NotAffected,
        products: ['pkg:composer/k2gl/dsse@1.3.0'],
        justification: Justification::VulnerableCodeNotInExecutePath,
    )
    ->toJson();
```

A product is any IRI or [package URL](https://github.com/package-url/purl-spec); pass a
string for the common case, or a full `Product` (with subcomponents, hashes and other
identifiers) when you need it. `build()` returns the `Document` instead of JSON and stamps
its canonical `@id`.

### Read and query a document

```php
use K2gl\OpenVex\Document;
use K2gl\OpenVex\Status;

$document = Document::fromJson($json);

foreach ($document->statementsFor('pkg:composer/k2gl/dsse@1.3.0') as $statement) {
    if ($statement->status === Status::NotAffected) {
        // suppress this CVE for that product, with $statement->justification as the reason
    }
}
```

`statementsFor()` matches an IRI, purl, CPE or hash digest against each statement's
products and their subcomponents.

### Canonical identity

Two documents with the same impact statements always get the same `@id`, regardless of
metadata. That makes documents content-addressable and easy to deduplicate.

```php
$document->canonicalHash(); // "8ed99017…" — sha256 over the statements only
$document->generateId();    // "https://openvex.dev/docs/public/vex-8ed99017…"
```

## Design

- The status rules of the spec (`not_affected` needs a justification or an impact
  statement, `affected` needs an action statement, and so on) are checked in the
  `Statement` constructor — parsing an invalid document throws rather than yielding a
  half-valid object.
- Canonicalization follows go-vex exactly and is verified against its published test
  vectors. Where go-vex leaves component hash/identifier ordering to Go's random map
  iteration, this port sorts the keys, which is identical for the single-entry maps that
  occur in practice and deterministic otherwise.
- Timestamps finer than microseconds (Go emits nanoseconds) are truncated on parse; the
  canonical hash only uses whole seconds, so a document's identity is unaffected.

## License

MIT — see [LICENSE](LICENSE).
