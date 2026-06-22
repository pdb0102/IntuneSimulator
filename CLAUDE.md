# Repo conventions

This repo is the **SCEPwright** SCEP testing suite (IntuneSimulator + ScepWright client/server).

## ScepWright client/server code style (src/ScepWright.*, tests/ScepWright.Tests)
- **Never `var`** — always the explicit type (enforced by `.editorconfig`).
- **Declare locals at the top of the block, unassigned, then a blank line, then assignments.** Example:

  ```csharp
  int count;
  string name;

  count = items.Length;
  name = items[0].Name;
  ```
- No exceptions for control flow: static `Create()`/`Load()` factories; sync returns a result enum + `out value` + `out string error`; async returns `ScepResult<T>`.
- The `IScepCrypto` crypto contract uses **bool-discriminated** results (`bool` + `out value` + `out string error`) rather than the `ScepClientResult` enum returned by the `Create()` factories. Both forms obey the no-exceptions-for-control-flow rule, so the bool form is **not** a violation of the "returns a result enum" wording above.
- All cryptography goes through `IScepCrypto`; never reference a crypto library outside `ScepWright.Crypto.*`.

The existing IntuneSimulator projects keep their modern idioms (`var`, LINQ); these rules apply to ScepWright client/server code only.
