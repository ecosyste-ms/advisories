{ release, system, namesFile }:
let
  pkgs = import release { inherit system; config.allowUnfree = true; };
  names = builtins.fromJSON (builtins.readFile namesFile);
  inspect = attr:
    let
      parts = attr.parts;
      pkg = pkgs.lib.attrByPath parts (throw "attribute missing") pkgs;
      inputs = pkgs.lib.toList (pkg.drvAttrs.patches or []);
      row = if inputs == [] then null else {
        attr = attr.name;
        pname = pkg.pname or (throw "missing pname");
        version = pkg.version or (throw "missing version");
        inherit (pkg) system;
        output = toString pkg;
        derivation = pkg.drvPath;
        patches = map toString inputs;
      };
      result = builtins.tryEval (builtins.deepSeq row row);
    in if result.success then result.value else { attr = attr.name; error = "evaluation failed"; };
in builtins.filter (row: row != null) (map inspect names)
