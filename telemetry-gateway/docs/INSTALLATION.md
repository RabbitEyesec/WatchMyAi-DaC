# Gateway installation boundary

The gateway has no component-local installation workflow. Use the root
[`QUICKSTART.md`](../../QUICKSTART.md), which is authoritative for installation, setup,
verification, and validation. Setup creates the private runtime home, direct Elastic output,
policy mode, hooks, Fleet integration, Elastic assets, and rules. The lower-level `init`, `policy`,
and integration commands remain administrative primitives used by setup and are not a competing
first-user workflow.

Signed production setup accepts an organization root and signed release through `watchmyai setup`.
Development setup automatically generates the restrictive development policy; users do not create
or sign JSON manually.
