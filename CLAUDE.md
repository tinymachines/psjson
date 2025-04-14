# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands
- Build: `gcc -o psjson psjson.c` or `./buildit.sh`
- Run: `./psjson`
- No test suite provided

## Code Style Guidelines
- C99 standard
- 4-space indentation
- Function prototypes declared before main()
- Snake_case for function and variable names
- Error handling with proper cleanup and return codes
- Memory management: allocate with malloc/realloc, free when done
- Use descriptive variable names
- Comment functions with brief descriptions
- Limit line length to ~80 characters
- Include appropriate headers
- Initialize all variables before use
- Error messages should go to stderr with perror()
- Check return values from system calls