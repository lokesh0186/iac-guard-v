"""Explicit version/property qualification, separate from JSON adapter support."""
from __future__ import annotations

from email.parser import Parser
import hashlib
import json
from pathlib import Path

from .models import DomainError
from .fingerprints import canonicalize_kubernetes_identity, canonicalize_terraform_address

_DATA = json.loads((Path(__file__).parent/'adapters/checkov_profiles.json').read_text())
QUALIFIED_VERSIONS = tuple(_DATA['versions'])
AUTHORITY_PROFILE = 'CHECKOV_3_3_REVIEWED_PATHS_V1'


def authority_properties(version: str) -> tuple[str, ...]:
    return tuple(_DATA['versions'].get(version,{}).get('properties',()))


def authority_details(version: str) -> dict[str, str]:
    profile = _DATA['versions'].get(version)
    if profile is None:
        return {}
    return {name: profile[name] for name in ('policy_variant', 'policy_qualification_identity')}


class CheckovAuthorityUnavailable(DomainError):
    reason = 'CHECKOV_VERSION_UNSUPPORTED_FOR_REQUESTED_PROPERTY'


def property_supported(version: str, rule: str, resource_address: str | None = None) -> bool:
    if version == '3.3.0':
        return True  # Retain the existing released contract, not a new promotion.
    profile = _DATA['versions'].get(version)
    if profile is None or rule not in profile['properties']:
        return False
    if resource_address is not None:
        # The qualified Kubernetes policies are source-manifest checks, not
        # same-ID Terraform-provider implementations. Protected adapter identities
        # distinguish Kubernetes slash identities from Terraform addresses.
        try:
            canonicalize_terraform_address(resource_address)
            framework = 'terraform'
        except DomainError:
            parts = resource_address.rsplit('/',3)
            if len(parts) != 4:
                return False
            try:
                canonicalize_kubernetes_identity(*parts)
            except DomainError:
                return False
            framework = 'kubernetes'
        if framework != profile['property_definitions'][rule]['framework']:
            return False
    return True


def require_authority(version: str, rules: tuple[str, ...] = (), *, resources: tuple[str, ...] = ()) -> None:
    if resources and len(resources) != len(rules):
        raise DomainError('Authority rules and resources must correspond')
    unavailable = [r for i,r in enumerate(rules)
                   if not property_supported(version,r,resources[i] if resources else None)]
    if version not in QUALIFIED_VERSIONS or unavailable:
        raise CheckovAuthorityUnavailable(
            f'Installed Checkov: {version}; outside the supported authority for the requested property; supported authority profile: {AUTHORITY_PROFILE}; '
            f'qualified versions: {", ".join(QUALIFIED_VERSIONS)}; '
            f'unqualified requested properties: {", ".join(unavailable) or "version not qualified"}. '
            'Select a qualified version/property or run native IaC-Guard-V properties, which remain available.'
        )


def installed_version(executable: Path) -> str:
    if not executable.is_file():
        return '3.3.0'  # The legacy path still requires its real executable/probe.
    from .external_checkov import load_manifest
    external = load_manifest(executable,verify=False)
    if external is not None:
        return external['version']
    lines=executable.read_bytes().splitlines()
    if lines and lines[0].startswith(b'#!/'):
        prefix=Path(lines[0][2:].decode().split()[0]).parent.parent
        metadata=sorted(prefix.glob('lib/python*/site-packages/checkov-*.dist-info/METADATA'))
        if len(metadata)==1:
            value=Parser().parsestr(metadata[0].read_text())['Version']
            if value:
                return value
    # Historical minimal launchers may not expose package metadata. They retain
    # the exact 3.3.0 probe requirement; no unknown version is promoted by this.
    return '3.3.0'


def require_published_package(version: str, files: dict[str,str]) -> None:
    profile=_DATA['versions'].get(version)
    if profile is None:
        require_authority(version)
    actual=hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if actual != profile['package_source_digest']:
        raise DomainError('Checkov source does not match the qualified published package')


def require_published_launcher(version: str, source: bytes) -> None:
    profile = _DATA['versions'].get(version)
    if profile is not None:
        body = source.partition(b'\n')[2]
        if hashlib.sha256(body).hexdigest() != profile['launcher_body_sha256']:
            raise DomainError('Checkov console script does not match the published launcher')
