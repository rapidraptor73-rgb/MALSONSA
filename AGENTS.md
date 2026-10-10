# Branch and merge workflow

- `main` contains only completed, tested, stable releases. Never develop features or commit directly on `main`.
- Publish or merge into `main` only when the user explicitly asks for main publication. Passing tests alone does not authorize main publication. Keep completed features on `develop` until that request. GitHub release/tag publication also requires an explicit user request.
- `develop` is the integration branch. Start every feature from the latest `develop` on a new `feature/<descriptive-name>` branch.
- Implement and validate the feature on its feature branch. Merge it into `develop` only after the feature is complete and relevant tests pass.
- After integrating features, run the project's available tests, build, and relevant integration checks on `develop`. Resolve failures on feature branches and integrate the fixes before proceeding.
- Merge `develop` into `main` only when the integrated version is complete, all required checks pass, and no known regressions remain. If checks are unavailable, report that limitation instead of claiming validation passed.
- Prefer pull requests for `feature/*` into `develop` and for `develop` into `main`, recording validation results in the PR description.
- Do not bypass this workflow unless the user explicitly requests an exception.
