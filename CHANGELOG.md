# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Types of changes

- `Added` for new features.
- `Changed` for changes in existing functionality.
- `Deprecated` for soon-to-be removed features.
- `Removed` for now removed features.
- `Fixed` for any bug fixes.
- `Security` in case of vulnerabilities.

## [Unreleased]

Nothing in the backlog !

## [0.1.0]

- `Added` Passwords stored encrypted with master password (AES256 with salt) in `~/.credentials/store.yaml`.
- `Added` Master password can be provided by environment (`DOCKER_CREDENTIAL_MASTER_PASSWORD`) or terminal prompt.
- `Added` Go package `github.com/adrienaury/docker-credential-localuser/pkg/passwords` can be directly linked (gives possibility to use master password prompt).
