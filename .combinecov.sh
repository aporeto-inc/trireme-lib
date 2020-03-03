#!/usr/bin/env bash

if [ -f "coverage.windows.txt" ]; then
	cat coverage.txt coverage.windows.txt > coverage.combined.txt
	mv coverage.combined.txt coverage.txt
fi
