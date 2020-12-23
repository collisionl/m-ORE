#!/bin/bash
make clean
make
./tests/test_cash_ore < ~/Downloads/pbc-0.5.14/param/d159.param
# ./tests/time_cash_ore < ~/Downloads/pbc-0.5.14/param/d159.param