# Contributing to EQUS SDK

Issues and pull requests are welcome. Open an issue before writing anything non-trivial, and report
security problems privately rather than in a public issue.

| Area | Expectation |
| --- | --- |
| Pull request scope | One logical change per pull request. State what changed, why, and how you verified it. Call out breaking changes to the public API or to a wrapper's surface. |
| Tests | Unit tests beside the code, e2e tests in [`tests/e2e`](tests/e2e). See [tests design](docs/guidelines/tests-design.md). |
| Guidelines | Follow the [development guidelines](docs/guidelines/dev.md), in particular [error handling](docs/guidelines/error_handling.md) and [logging](docs/guidelines/logging.md). Never log key material, credential contents, or PII. |
| Wrappers | A new public API usually needs matching surface in the [Node.js](wrappers/nodejs), [WASM](wrappers/wasm), and [UniFFI](wrappers/uniffi) wrappers, or a note saying why it is native-only. |
| AI-assisted contributions | Fine under [`docs/AI_CONSTITUTION.md`](docs/AI_CONSTITUTION.md). You are still responsible for reviewing and explaining every line you submit. |
| Releases | Cut by maintainers ([release guide](docs/guidelines/release.md)). Do not bump versions in a pull request. |
| Licensing | Contributions are accepted under the [Apache License 2.0](./LICENSE). Update [`THIRD-PARTY-NOTICE`](THIRD-PARTY-NOTICE) if a new dependency needs attribution. |
