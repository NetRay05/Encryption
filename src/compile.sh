#!/bin/bash
COMMAND=`g++ enc.cpp -o enc -Os -Wall -Wno-deprecated -std=c++20 -lcryptopp -fsanitize=address && g++ dec.cpp -o dec -Os -Wall -Wno-deprecated -lcryptopp -std=c++20 -fsanitize=address`
echo "Compiling..."
echo $COMMAND
echo "Compiled!"