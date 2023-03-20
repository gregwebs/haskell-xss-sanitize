{
  description = "run untrusted HTML through Text.HTML.SanitizeXSS.sanitizeXSS to prevent XSS attacks. see README.md <http://github.com/yesodweb/haskell-xss-sanitize> for more details";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    nix-filter.url = "github:numtide/nix-filter/main";
  };

  outputs = { self, nixpkgs, nix-filter }: 
    let
      pkgs = import nixpkgs { system = "x86_64-linux"; };

      ghcVersion = "810";

      src = nix-filter.lib {
        root = ./.;
        include = [
          (nix-filter.lib.inDirectory "src")
          (nix-filter.lib.inDirectory "test")
          (nix-filter.lib.matchExt "hs")
          ./LICENSE
          ./xss-sanitize.cabal
          ./package.yaml
        ];
      };

      xss-sanitize = hself: hself.callCabal2nix "xss-sanitize" src {};

      myHaskellPackages = pkgs.haskell.packages."ghc${ghcVersion}".override {
        overrides = hself: hsuper: {
          xss-sanitize = xss-sanitize hself;
        };
      };

      shell = myHaskellPackages.shellFor {
        packages = p: [
          p.xss-sanitize
        ];
        buildInputs = with pkgs.haskell.packages."ghc${ghcVersion}"; [
          myHaskellPackages.cabal-install
          ghcid
          (pkgs.haskell-language-server.override { supportedGhcVersions = [ "${ghcVersion}" ]; })
          hlint
        ];
        withHoogle = true;
        doBenchmark = true;
      };

    in
      {
        inherit xss-sanitize;
        devShell.x86_64-linux = shell;
      };
}
