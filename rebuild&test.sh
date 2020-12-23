#!/bin/bash
make clean
make
./tests/test_ore < ~/Downloads/pbc-0.5.14/param/d159.param
# ./tests/time_ore < ~/Downloads/pbc-0.5.14/param/d159.param
# ./tests/test_ore < ~/Downloads/pbc-0.5.14/param/d224.param // 为什么无法初始化