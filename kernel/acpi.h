#ifndef NXTS_ACPI_H
#define NXTS_ACPI_H
#include "common.h"

/* ACPI poweroff (core CLI family (b)). Tables are parsed, never
   assumed: RSDP -> RSDT -> FADT -> DSDT _S5 package. If any step
   fails, poweroff reports unavailable instead of writing a guessed
   SLP_TYP to a guessed port (a wrong value powers off nothing or,
   worse, writes to an unrelated device). */

/* Parse and validate the tables once; caches the result.
   Returns 0 when a usable PM1 control block + SLP_TYP were found,
   -1 otherwise. Safe to call repeatedly. */
int  acpi_init(void);
/* 1 if acpi_init() succeeded, 0 otherwise. */
int  acpi_available(void);
/* Power off via the PM1 control block(s). Does not return on
   success (the machine powers off, then the CPU halts). Returns
   -1 when ACPI poweroff is unavailable — the caller must then
   halt with a message, never pretend the machine powered off. */
int  acpi_poweroff(void);
/* Print the parsed ACPI state (or the failure stage) to the
   console. Diagnostic for `diag acpi` and for shutdown
   debugging; it never powers anything off. */
void acpi_diag(void);

#endif
