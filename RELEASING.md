# Release process

SimpleSCEP uses semantic version tags such as `v0.1.0`. The release workflow publishes a multi-platform image to GitHub Container Registry, attaches build provenance and an SBOM attestation, and creates a GitHub release with digest checksums.

## Before tagging

1. Work from the clean, sanitized public repository—not the historical commercial repository.
2. Update `CHANGELOG.md`, including the release date and final version heading.
3. Generate assets and templates, then run `go test ./...` and build the container from scratch.
4. Start the image against a fresh PostgreSQL database and exercise first-run setup and the supported enrollment protocols.
5. Scan the exact commit for secrets, private keys, dependency vulnerabilities, incompatible licenses, commercial billing remnants, and private deployment identifiers.
6. Confirm the repository's security settings, required checks, and private vulnerability reporting are enabled.

## Publish

Create and push an annotated tag from the verified commit:

```sh
git tag -a v0.1.0 -m "SimpleSCEP v0.1.0"
git push origin v0.1.0
```

Verify the GitHub Actions run, release notes, GHCR image, digest, provenance, and SBOM before announcing the release. Keep the `v0.1.0` example aligned with the version being published.
