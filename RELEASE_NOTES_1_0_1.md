# IaC-Guard-V 1.0.1

This maintenance release corrects a Git tree validation gap reported by Maxym
Vlasov in [#41](https://github.com/lokesh0186/iac-guard-v/issues/41).

Recursive Git tree listings must not contain a non-directory leaf path that is
also an ancestor of another leaf. The materializer now rejects those conflicting
paths with `DomainError` before creating file or symlink objects. Legitimate
nested directories and standalone symlinks keep their supported behavior.

The report concerns fail-closed handling of fsck-invalid local Git content in the
documented operator-controlled workflow. Source review supports the reported
validation flaw. Regression tests use synthetic listings and exercise validation
only.

The existing 18 native V1 properties, schemas, public interfaces, and supported
Python 3.10–3.13 range retain their 1.x contract. Upgrade with:

```bash
python -m pip install 'iac-guard-v==1.0.1'
```

The evolving software archive uses the
[Zenodo concept DOI](https://doi.org/10.5281/zenodo.22088272).

Implementation and release preparation were assisted by Codex.
