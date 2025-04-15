#!/bin/bash

gcc -o psjson psjson.c
sudo ln -s $(pwd)/psjson /usr/bin/psjson
