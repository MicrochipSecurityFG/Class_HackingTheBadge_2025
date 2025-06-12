/** \file bip32.h
  *
  * \brief Describes function and constants exported and used by bip32.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef BIP32_H_INCLUDED
#define BIP32_H_INCLUDED

#include "bignum256.h"
#include "common.h"

/** Length (in number of bytes) of a BIP32 node, a.k.a. extended private
  * key. */
#define NODE_LENGTH		64

extern void bip32SeedToNode(uint8_t *master_node, const uint8_t *seed, const unsigned int seed_length);
//extern bool bip32DerivePrivate(BigNum256 out, const uint8_t *master_node, const uint32_t *path, const unsigned int path_length);
extern bool bip32DerivePrivate(BigNum256 out, uint8_t *chain_code_out, const uint8_t *master_node, const uint32_t *path, const unsigned int path_length);
bool bip32DeriveNextPrivate(BigNum256 out, uint8_t *chain_code_out, const uint8_t *parent_node, uint32_t index);
#endif // #ifndef BIP32_H_INCLUDED
