with import <nixos-unstable> {};
runCommand "dummy" { buildInputs = [ go_1_26 gnumake gcc ]; } ""
