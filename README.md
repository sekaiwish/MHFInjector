# MHFInjector
MHFInjector is a simple client patcher for Monster Hunter Frontier.
It uses [Detours](https://github.com/microsoft/Detours) to hook and patch the game in various ways.

## Usage
- Move `MHFLoader.exe` and `MHFPatcher.dll` to the game's directory.
- Run `MHFLoader.exe` as administrator.

You may also use the following command line arguments to run the game from elsewhere:
`MHFLoader.exe -exe <path/to/mhf.exe> -dll <path/to/MHFPatcher.dll>`

## Features
- Bypasses the game's GameGuard initialization.
- Disables the game's anti-tamper checks.