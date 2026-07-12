# Changelog

## 1.0.0

- Initial release: read, write and canonicalize OpenVEX documents.
- Immutable value objects for the full v0.2.0 model (`Document`, `Statement`,
  `Vulnerability`, `Product`, `Subcomponent`) with the status/justification rules
  enforced on construction, plus the `Status` and `Justification` enums.
- `Document::fromJson()` / `toJson()` and the `OpenVex` fluent builder for authoring.
- `Document::canonicalHash()` and `generateId()` produce the deterministic document
  `@id`, verified against the go-vex reference test vectors.
- `Document::statementsFor()` resolves the statements covering a given IRI, purl, CPE
  or hash digest.
