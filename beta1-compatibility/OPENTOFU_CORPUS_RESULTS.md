# Beta1 OpenTofu compatibility corpus results

Manifest SHA-256: `508e44acf16beef48c794e02b389039b080bcca29a5727b31df4270836f67446`

The manifest was frozen before semantic execution. All repositories were checked out
at the exact commits in the manifest. `opentofu/registry` and the Terragrunt example
were excluded before execution because neither retained candidate exposed a direct
OpenTofu/Terraform module root.

| Case | Classification | Evidence |
| --- | --- | --- |
| OpenTofu official multiple-block fixture | `SUPPORTED` | 1 effective file, 1 resource, complete source set; digest `ba61b8eac023afd98a18be2bc3329d77c2a05ff4f09af0fbc9b48cadb23c622f`. |
| Azure ALZ root | `PARTIAL` | 22 files and 26 resources protected; a remote module remains explicitly unsupported; digest `30af2d23856d96b3ed9ec1bec45d68313f6bd3bbbe7314eeb260e92da44ea860`. |
| vehagn home-assistant | `SUPPORTED` | 4 files, 3 resources; the predeclared VM disk image reference returned `SATISFIED`; digest `5c674b4da85ccfd99390058d79eda5dc25d4151772b3e3a066230e6283d8903b`. |
| GenAI prerequisites | `PARTIAL` | 4 files and 3 resources protected; three remote modules retained as unsupported evidence; digest `689059342c3244302a574fc00d3a7813e1acd16246fadb16d45505b43fe18b7f`. |
| filterql root | `PARTIAL` | The effective `.tofu` file was protected; its absent local module remained typed incomplete evidence; digest `baebb6df6447d4b289bc9e3c8ca163307ecb60bda2943b1062a1440aade1d6fd`. |
| AWS VPC module root | `PARTIAL` | 5 files and 79 resources protected; the predeclared counted source resource returned `NOT_EVALUATED` with `OPENTOFU_INSTANCE_IDENTITY_UNRESOLVED`; digest `80a383edca55668f7932584605e021a27c6e8d0478f8a392f8f2a16f361c1e17`. |
| Cloud Posse TGW hub | `FAIL_CLOSED` | A local module escaped the selected protected root; the loader rejected the root rather than acquiring or trusting external bytes. |

Totals: `SUPPORTED=2`, `PARTIAL=4`, `FAIL_CLOSED=1`. These are bounded static
compatibility results, not claims of complete project or OpenTofu support.
