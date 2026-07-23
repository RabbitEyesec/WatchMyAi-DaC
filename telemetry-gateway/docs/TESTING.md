# Testing and verification

For a configured clone:

```bash
.venv/bin/watchmyai verify
.venv/bin/watchmyai validate
```

`verify` emits and locates a unique gateway event and proves configuration, policy, Elastic, Fleet,
Agent, asset, and 20-rule state. `validate` generates all current scenarios and requires 20/20
current alerts. `validate --static-only` is the explicit maintainer tier and cannot be presented as
live evidence.

The standalone wheel command `watchmyai self-check` validates packaged schema, normalizer,
signatures, and active policy resources without claiming external alert readiness. CI uses the
repository-only setup/verify path plus the public static-validation option.
