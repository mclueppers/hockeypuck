with import <nixos-unstable> {};
runCommand "dummy" { buildInputs = [ go_1_20 gnumake gcc ]; } ""
