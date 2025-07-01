with import <nixos-unstable> {};
runCommand "dummy" { buildInputs = [ go_1_24 gnumake gcc ]; } ""
