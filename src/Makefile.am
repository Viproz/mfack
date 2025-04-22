AM_CFLAGS  = @libnfc_CFLAGS@

bin_PROGRAMS = mfack

noinst_HEADERS = crapto1.h mfack.h mifare.h nfc-utils.h

mfack_SOURCES = crapto1.c crypto1.c mfack.c mifare.c nfc-utils.c
mfack_LDADD   = @libnfc_LIBS@

dist_man_MANS = mfack.1
