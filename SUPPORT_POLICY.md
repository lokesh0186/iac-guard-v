# Support policy

IaC-Guard-V 1.x supports Python 3.10 through 3.13 and the bounded semantics in
[SUPPORTED_SCOPE.md](SUPPORTED_SCOPE.md). Python 3.14 is not supported by 1.0.

The current 1.x minor line receives correctness, security, compatibility, and
documentation fixes. A supported patch never changes a V1 property's meaning or
invalidates an existing supported contract. New property families require a versioned
minor release and cannot reinterpret an existing ID.

Open a public issue for a minimal non-sensitive bug reproduction. Use the private
GitHub security-advisory channel for a suspected false `SATISFIED` result, credential
exposure, integrity bypass, or security-boundary defect. Include the exact product
version, property or contract version, protected input identity, report, expected
result, and smallest shareable fixture.

Do not post private infrastructure, credentials, scanner caches, or undisclosed
third-party evidence. Third-party scanner support is limited to the versions and
authority described in [SCANNER_AUTHORITY.md](SCANNER_AUTHORITY.md).
