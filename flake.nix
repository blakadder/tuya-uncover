{
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      pylibs = with pkgs.python3Packages; [
        requests
      ];
      app = "uncover.py";
    in
    {
      devShells.${system}.default = pkgs.mkShell {
        packages = pylibs;
      };

      apps.${system}.default = {
        type = "app";
        program = "${
          pkgs.writers.writePython3Bin "run" {
            doCheck = false;
            libraries = pylibs;
          } ./${app}
        }/bin/run";
      };
    };
}
