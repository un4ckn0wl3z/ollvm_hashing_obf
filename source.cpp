#include <iostream>

#include <string>

#include <Windows.h>

#define INITIAL_SEED 7

UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String) {
  SIZE_T Index = 0;
  UINT32 Hash = 0;
  SIZE_T Length = lstrlenA(String);

  while (Index != Length) {
    Hash += String[Index++];
    Hash += Hash << INITIAL_SEED;
    Hash ^= Hash >> 6;
  }

  Hash += Hash << 3;
  Hash ^= Hash >> 11;
  Hash += Hash << 15;

  return Hash;
}

void xor_stringInp(PBYTE str, char key) {
  for (int i = 0; i < 18; i++) {
    str[i] ^= key;
  }
  str[18] = '\0';
}

void xor_stringPass(PBYTE str, char key) {
  for (int i = 0; i < 9; i++) {
    str[i] ^= key;
  }
  str[9] = '\0';
}

void xor_stringFail(PBYTE str, char key) {
  for (int i = 0; i < 7; i++) {
    str[i] ^= key;
  }
  str[7] = '\0';
}

int main() {

  byte inp[] = {
    0xef,
    0xc4,
    0xde,
    0xcf,
    0xd8,
    0x8a,
    0xde,
    0xc2,
    0xcf,
    0x8a,
    0xda,
    0xcb,
    0xd9,
    0xd9,
    0xdd,
    0xc5,
    0xd8,
    0xce
  };
  byte pass[] = {
    0xed,
    0xc5,
    0xc5,
    0xce,
    0x8a,
    0xe0,
    0xc5,
    0xc8,
    0x8b
  };
  byte fail[] = {
    0xee,
    0xcf,
    0xc4,
    0xc3,
    0xcf,
    0xce,
    0x8b
  };
  char key = 0xaa; // Example key for XOR operation

  PCHAR password;

  xor_stringInp(inp, key); // XOR again to revert to original
  xor_stringPass(pass, key);
  xor_stringFail(fail, key);

  std::cout << inp << std::endl;
  std::cin >> password;

  if (HashStringJenkinsOneAtATime32BitA(password) == 0x41FBD77D) {
    std::cout << pass << std::endl;
  } else {
    std::cout << fail << std::endl;
  }

  return 0;
}
