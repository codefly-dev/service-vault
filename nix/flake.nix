{
  description = "codefly vault service: nix runtime (Docker-free)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    in
    {
      # devShell exposes the vault server/CLI so the codefly NixEnvironment runs
      # `vault server -dev` via the materialized devShell. HashiCorp Vault is BUSL
      # (unfree), so nixpkgs is instantiated with allowUnfree — done in-flake (pure;
      # no --impure / global config needed).
      devShells = forAllSystems (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            config.allowUnfree = true;
          };
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.vault-bin
            ];
          };
        });
    };
}
