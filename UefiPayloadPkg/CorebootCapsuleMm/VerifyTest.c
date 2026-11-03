/** @file
  Host checks for the production bounded capsule verifier.
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pkcs7.h>
#undef NULL
#include <Library/CapsuleVerifyLib.h>
VOID *EFIAPI
CopyMem(VOID *d, CONST VOID *s, UINTN n)
{
  return memcpy(d, s, n);
}
INTN EFIAPI
CompareMem(CONST VOID *a, CONST VOID *b, UINTN n)
{
  return memcmp(a, b, n);
}
static int Mutate;
static BOOLEAN
Read(VOID *c, UINTN o, VOID *b, UINTN n)
{
  FILE *f = c;
  if (fseek(f, (long)o, SEEK_SET) || fread(b, 1, n, f) != n)
    return FALSE;
  if (Mutate && o <= 4096 && 4096 < o + n)
    ((UINT8 *)b)[4096 - o] ^= 1;
  return TRUE;
}
static UINT8 *
Load(const char *p, UINTN *n)
{
  FILE *f = fopen(p, "rb");
  if (!f)
    exit(2);
  fseek(f, 0, SEEK_END);
  *n = ftell(f);
  rewind(f);
  UINT8 *b = malloc(*n);
  if (!b || fread(b, 1, *n, f) != *n)
    exit(2);
  fclose(f);
  return b;
}
int
main(int argc, char **argv)
{
  if (argc != 6)
    return 2;
  UINTN             ns, nr;
  UINT8            *s = Load(argv[2], &ns), *r = Load(argv[3], &nr);
  FILE             *f = fopen(argv[1], "rb");
  CAPSULE_VERIFIER *v = calloc(1, sizeof(*v));
  if (!f || !v)
    return 2;
  v->Read    = Read;
  v->Context = f;
  fseek(f, 0, SEEK_END);
  v->SignedSize = ftell(f);
  rewind(f);
  v->ImageOffset = strtoul(argv[4], 0, 0);
  v->ImageSize   = strtoul(argv[5], 0, 0);
  if (!CapsuleVerify(v, s, ns, r, nr))
    return 3;
  UINTN content_size;
  UINT8 *content = Load(argv[1], &content_size);
  if (v->MetadataSize != content_size - v->ImageSize ||
      memcmp(v->Metadata, content, v->ImageOffset) ||
      memcmp(v->Metadata + v->ImageOffset,
             content + v->ImageOffset + v->ImageSize,
             content_size - v->ImageOffset - v->ImageSize))
    return 14;
  free(content);
  const unsigned char *cursor = s;
  PKCS7 *message = d2i_PKCS7(NULL, &cursor, (long)ns);
  if (!message)
    return 8;
  int raw_size = i2d_PKCS7_SIGNED(message->d.sign, NULL);
  unsigned char *raw = malloc(raw_size > 0 ? (size_t)raw_size : 1);
  unsigned char *output = raw;
  if (!raw || raw_size <= 0 || i2d_PKCS7_SIGNED(message->d.sign, &output) != raw_size)
    return 9;
  if (!CapsuleVerify(v, raw, raw_size, r, nr))
    return 10;
  free(raw);
  PKCS7_free(message);
  for (UINTN i = 0; i < v->BlockCount; i++)
    if (!CapsuleReadVerifiedBlock(v, i))
      return 4;
  Mutate = 1;
  if (CapsuleReadVerifiedBlock(v, 0) || v->Verified)
    return 5;
  if (CapsuleVerify(v, s, ns, r, nr))
    return 6;
  Mutate = 0;
  v->ImageSize++;
  if (CapsuleVerify(v, s, ns, r, nr) || v->Verified || CapsuleReadVerifiedBlock(v, 0))
    return 11;
  v->ImageSize--;
  if (!CapsuleVerify(v, s, ns, r, nr))
    return 12;
  if (!CapsuleTrustValid(r, nr) || CapsuleTrustValid(r, 0) ||
      CapsuleTrustValid(r, nr - 1) || CapsuleTrustValid((CONST UINT8 *)"invalid", 7))
    return 14;
  r[nr / 2] ^= 1;
  if (CapsuleVerify(v, s, ns, r, nr) || v->Verified)
    return 13;
  r[nr / 2] ^= 1;
  s[ns / 2] ^= 1;
  if (CapsuleVerify(v, s, ns, r, nr))
    return 7;
  puts("Production capsule verifier: signature, verified blocks, source mutation and bad signature "
       "checks passed");
  fclose(f);
  free(v);
  free(s);
  free(r);
  return 0;
}
