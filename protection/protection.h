#pragma once
///////////////////////////////////////////////////////////////////////////////
//  Protection Toolkit — Master Include
//
//  Software protection through multiple defensive layers:
//
//  Layer 1: String Encryption    — No plaintext strings in binary
//  Layer 2: VM Obfuscation       — Critical code runs as encrypted bytecode
//  Layer 3: Control Flow         — Flattening + opaque predicates
//  Layer 4: Anti-Analysis        — Debugger + timing + integrity checks
//
//  Usage: #include "protection/protection.h"
///////////////////////////////////////////////////////////////////////////////

// Core VM
#include "vm_defs.h"
#include "vm_engine.h"
#include "vm_compiler.h"
#include "vm_hash.h"

// String protection
#include "string_crypt.h"

// Runtime protection
#include "anti_analysis.h"

// Control flow obfuscation
#include "control_flow.h"
