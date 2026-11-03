/** @file
  Verify capsule data without allocating an image-sized buffer.
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Library/CapsuleVerifyLib.h>
#include <Library/BaseMemoryLib.h>
#include <limits.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

STATIC
int
ReadSignedBytes (BIO *Bio, char *Output, int Capacity)
{
  CAPSULE_VERIFIER *State;
  UINTN Size;
  UINTN Start;
  UINTN End;
  UINTN Take;
  UINTN MetadataStart;
  UINTN ImageEnd;
  unsigned int DigestSize;

  State = BIO_get_data (Bio);
  if ((State == NULL) || (Output == NULL) || (Capacity <= 0) || State->Failed) {
    return -1;
  }

  Size = State->SignedSize - State->Position;
  if (Size > (UINTN)Capacity) {
    Size = (UINTN)Capacity;
  }
  if (Size > sizeof (State->Buffer)) {
    Size = sizeof (State->Buffer);
  }
  if (Size == 0) {
    return 0;
  }

  if (!State->Read (State->Context, State->Position, State->Buffer, Size)) {
    State->Failed = TRUE;
    return -1;
  }

  /* Keep policy metadata from the very same snapshots being authenticated.
     The owner must not reread a mutable header or manifest after verification. */
  ImageEnd = State->ImageOffset + State->ImageSize;
  if (State->Position < State->ImageOffset) {
    Take = State->ImageOffset - State->Position;
    if (Take > Size) {
      Take = Size;
    }
    CopyMem (State->Metadata + State->Position, State->Buffer, Take);
  }
  MetadataStart = State->Position > ImageEnd ? State->Position : ImageEnd;
  if (MetadataStart < State->Position + Size) {
    CopyMem (State->Metadata + State->ImageOffset + MetadataStart - ImageEnd,
              State->Buffer + MetadataStart - State->Position,
              State->Position + Size - MetadataStart);
  }

  /* Hash the same protected snapshot supplied to signature verification. */
  Start = State->Position;
  End = Start + Size;
  if (Start < State->ImageOffset) {
    Start = State->ImageOffset;
  }
  if (End > State->ImageOffset + State->ImageSize) {
    End = State->ImageOffset + State->ImageSize;
  }
  while (Start < End) {
    Take = CAPSULE_BLOCK_SIZE - State->BlockUsed;
    if (Take > End - Start) {
      Take = End - Start;
    }
    if (!EVP_DigestUpdate (State->BlockDigest,
                           State->Buffer + Start - State->Position, Take)) {
      State->Failed = TRUE;
      return -1;
    }
    State->BlockUsed += Take;
    Start += Take;
    if (State->BlockUsed == CAPSULE_BLOCK_SIZE) {
      if ((State->BlockCount >= CAPSULE_MAX_BLOCKS) ||
          !EVP_DigestFinal_ex (State->BlockDigest, State->Hashes[State->BlockCount], &DigestSize) ||
          (DigestSize != CAPSULE_SHA256_SIZE) ||
          !EVP_DigestInit_ex (State->BlockDigest, EVP_sha256 (), NULL))
      {
        State->Failed = TRUE;
        return -1;
      }
      State->BlockCount++;
      State->BlockUsed = 0;
    }
  }

  CopyMem (Output, State->Buffer, Size);
  State->Position += Size;
  return (int)Size;
}

STATIC
long
StreamControl (BIO *Bio, int Command, long Number, VOID *Pointer)
{
  CAPSULE_VERIFIER *State;

  (void)Number;
  (void)Pointer;
  State = BIO_get_data (Bio);
  if (Command == BIO_CTRL_FLUSH) {
    return 1;
  }
  if (Command == BIO_CTRL_EOF) {
    return (State != NULL) && (State->Position == State->SignedSize);
  }
  return 0;
}

STATIC
PKCS7 *
DecodeSignature (CONST UINT8 *Signature, UINTN Size)
{
  CONST unsigned char *Cursor;
  PKCS7 *Result;
  PKCS7_SIGNED *Signed;

  Cursor = Signature;
  Result = d2i_PKCS7 (NULL, &Cursor, (long)Size);
  if (Result != NULL) {
    if ((Cursor == Signature + Size) && PKCS7_type_is_signed (Result)) {
      return Result;
    }
    PKCS7_free (Result);
    return NULL;
  }

  /* Existing FMP authentication also accepts an unwrapped SignedData value. */
  Cursor = Signature;
  Signed = d2i_PKCS7_SIGNED (NULL, &Cursor, (long)Size);
  if ((Signed == NULL) || (Cursor != Signature + Size)) {
    PKCS7_SIGNED_free (Signed);
    return NULL;
  }
  Result = PKCS7_new ();
  if ((Result == NULL) || !PKCS7_set_type (Result, NID_pkcs7_signed)) {
    PKCS7_SIGNED_free (Signed);
    PKCS7_free (Result);
    return NULL;
  }
  PKCS7_SIGNED_free (Result->d.sign);
  Result->d.sign = Signed;
  return Result;
}

BOOLEAN
CapsuleVerify (CAPSULE_VERIFIER *State, CONST UINT8 *Signature,
               UINTN SignatureSize, CONST UINT8 *Root, UINTN RootSize)
{
  BIO_METHOD *Method = NULL;
  BIO *Stream = NULL;
  PKCS7 *Message = NULL;
  X509 *Certificate = NULL;
  X509_STORE *Store = NULL;
  CONST unsigned char *Cursor;

  if (State == NULL) {
    return FALSE;
  }
  State->Verified = FALSE;
  State->Position = 0;
  State->BlockUsed = 0;
  State->BlockCount = 0;
  State->Failed = FALSE;
  State->BlockDigest = NULL;
  State->MetadataSize = 0;
  if ((State->Read == NULL) || (Signature == NULL) || (SignatureSize == 0) ||
      (SignatureSize > INT_MAX) || (Root == NULL) || (RootSize == 0) ||
      (RootSize > INT_MAX) || (State->SignedSize > INT_MAX) ||
      (State->ImageOffset > State->SignedSize) ||
      (State->ImageSize > State->SignedSize - State->ImageOffset) ||
      (State->ImageSize == 0) || (State->ImageSize % CAPSULE_BLOCK_SIZE != 0) ||
      (State->ImageSize / CAPSULE_BLOCK_SIZE > CAPSULE_MAX_BLOCKS))
  {
    return FALSE;
  }
  State->MetadataSize = State->SignedSize - State->ImageSize;
  if (State->MetadataSize > sizeof (State->Metadata)) {
    return FALSE;
  }

  Message = DecodeSignature (Signature, SignatureSize);
  Cursor = Root;
  Certificate = d2i_X509 (NULL, &Cursor, (long)RootSize);
  Store = X509_STORE_new ();
  State->BlockDigest = EVP_MD_CTX_new ();
  Method = BIO_meth_new (BIO_TYPE_SOURCE_SINK, "protected capsule stream");
  if ((Message == NULL) || (Certificate == NULL) || (Cursor != Root + RootSize) ||
      (Store == NULL) || (State->BlockDigest == NULL) || (Method == NULL) ||
      !X509_STORE_add_cert (Store, Certificate) ||
      !X509_STORE_set_flags (Store, X509_V_FLAG_PARTIAL_CHAIN | X509_V_FLAG_NO_CHECK_TIME) ||
      !X509_STORE_set_purpose (Store, X509_PURPOSE_ANY) ||
      !EVP_DigestInit_ex (State->BlockDigest, EVP_sha256 (), NULL) ||
      !BIO_meth_set_read (Method, ReadSignedBytes) ||
      !BIO_meth_set_ctrl (Method, StreamControl))
  {
    goto Done;
  }
  Stream = BIO_new (Method);
  if (Stream == NULL) {
    goto Done;
  }
  BIO_set_init (Stream, 1);
  BIO_set_data (Stream, State);
  State->Verified = PKCS7_verify (Message, NULL, Store, Stream, NULL, PKCS7_BINARY) == 1 &&
                    !State->Failed && (State->Position == State->SignedSize) &&
                    (State->BlockUsed == 0) &&
                    (State->BlockCount == State->ImageSize / CAPSULE_BLOCK_SIZE);
Done:
  BIO_free (Stream);
  BIO_meth_free (Method);
  EVP_MD_CTX_free (State->BlockDigest);
  State->BlockDigest = NULL;
  X509_STORE_free (Store);
  X509_free (Certificate);
  PKCS7_free (Message);
  return State->Verified;
}

BOOLEAN
CapsuleReadVerifiedBlock (CAPSULE_VERIFIER *State, UINTN Block)
{
  UINT8 Digest[CAPSULE_SHA256_SIZE];
  unsigned int Size;

  if ((State == NULL) || !State->Verified || (Block >= State->BlockCount)) {
    return FALSE;
  }
  if (!State->Read (State->Context, State->ImageOffset + Block * CAPSULE_BLOCK_SIZE,
                    State->Buffer, sizeof (State->Buffer)) ||
      !EVP_Digest (State->Buffer, sizeof (State->Buffer), Digest, &Size, EVP_sha256 (), NULL) ||
      (Size != sizeof (Digest)) ||
      (CompareMem (Digest, State->Hashes[Block], sizeof (Digest)) != 0))
  {
    State->Verified = FALSE;
    return FALSE;
  }
  return TRUE;
}
