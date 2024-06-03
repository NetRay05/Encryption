#!/bin/bash
COMMAND=`g++ enc.cpp -o enc -Os -Wall -Wno-deprecated -std=c++20 -lz -lzip -lcryptopp && g++ dec.cpp -o dec -Os -Wall -Wno-deprecated -lz -lzip -lcryptopp -std=c++20`
echo "Compiling..."
echo $COMMAND
echo "Compiled!"
