/**
 * Copyright 2017, Philip Meulengracht
 *
 * This program is free software : you can redistribute it and / or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation ? , either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Vali ACPICA Support Layer (Tables Functions)
 *  - Missing implementations are todo
 */
#define __MODULE "ACPI"
#define __TRACE

#include <machine.h>
#include <vboot/uefi.h>
#include <debug.h>

#include <acpi.h>

#define _COMPONENT ACPI_OS_SERVICES
ACPI_MODULE_NAME("vali_kernel_tables")

static __EFI_GUID g_acpiGuid  = ACPI_TABLE_GUID;
static __EFI_GUID g_acpi2Guid = EFI_ACPI_20_TABLE_GUID;

/******************************************************************************
 *
 * FUNCTION:    AcpiOsGetRootPointer
 *
 * PARAMETERS:  None
 *
 * RETURN:      RSDP physical address
 *
 * DESCRIPTION: The ACPI specification is highly portable specification, however, 
 * it has a static part which is generally non-portable: the location of the Root System Descriptor Pointer. 
 * This pointer may be found in many different ways depending on the chipset. 
 * On PC-compatible computers (without EFI) it is located in lower memory generally 
 * somewhere between 0x80000 and 0x100000. However, even within the PC compatible platform, 
 * an EFI-enabled board will export the RSDP to the OS on when it loads it through the EFI system tables. 
 * Other boards on server machines which are not PC-compatibles, 
 * like embedded and handheld devices which implement ACPI will again, 
 * not all be expected to position the RSDP in the same place as any other board. 
 * The RSDP is therefore located in a chipset-specific manner; From the time the OS has the RSDP, 
 * the rest of ACPI is completely portable. However, the way the RSDP is found is not. 
 * This would be the reason that the ACPICA code wouldn't try to provide routines to expressly find the RSDP in a portable manner.
 *
 *****************************************************************************/
static int __IsRsdpPointer(const uint8_t* tablePointer)
{
    if (tablePointer[0] == 'R' && tablePointer[1] == 'S' && tablePointer[2] == 'D' && tablePointer[3] == ' ' &&
        tablePointer[4] == 'P' && tablePointer[5] == 'T' && tablePointer[6] == 'R' && tablePointer[7] == ' ') {
        return 1;
    }
    return 0;
}

static ACPI_PHYSICAL_ADDRESS
__CheckConfigurationGuid(__EFI_GUID guid)
{
    ACPI_PHYSICAL_ADDRESS physicalAddress = (ACPI_PHYSICAL_ADDRESS)__LocateGuidInConfigurationTable(
            (__EFI_CONFIGURATION_TABLE*)GetMachine()->BootInformation.ConfigurationTable,
            GetMachine()->BootInformation.ConfigurationTableCount,
            guid);
    if (physicalAddress) {
        void* table = AcpiOsMapMemory(physicalAddress, 0x1000);
        if (table) {
            int valid = __IsRsdpPointer(table);
            AcpiOsUnmapMemory(table, 0x1000);
            if (valid) {
                return physicalAddress;
            }
        }
    }
    return 0;
}

ACPI_PHYSICAL_ADDRESS
AcpiOsGetRootPointer (
    void)
{
    ACPI_PHYSICAL_ADDRESS physicalAddress = 0;

    if (GetMachine()->BootInformation.ConfigurationTable) {
        physicalAddress = __CheckConfigurationGuid(g_acpi2Guid);
        if (physicalAddress) {
            return physicalAddress;
        }
        physicalAddress = __CheckConfigurationGuid(g_acpiGuid);
        if (physicalAddress) {
            return physicalAddress;
        }
    }

	AcpiFindRootPointer(&physicalAddress);
	return physicalAddress;
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsPredefinedOverride
 *
 * PARAMETERS:  InitVal             - Initial value of the predefined object
 *              NewVal              - The new value for the object
 *
 * RETURN:      Status, pointer to value. Null pointer returned if not
 *              overriding.
 *
 * DESCRIPTION: Allow the OS to override predefined names
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsPredefinedOverride (
    const ACPI_PREDEFINED_NAMES *InitVal,
    ACPI_STRING                 *NewVal)
{
    if (!InitVal || !NewVal) {
		return (AE_BAD_PARAMETER);
	}

	*NewVal = NULL;
	return (AE_OK);
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsTableOverride
 *
 * PARAMETERS:  ExistingTable       - Header of current table (probably firmware)
 *              NewTable            - Where an entire new table is returned.
 *
 * RETURN:      Status, pointer to new table. Null pointer returned if no
 *              table is available to override
 *
 * DESCRIPTION: Return a different version of a table if one is available
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsTableOverride (
    ACPI_TABLE_HEADER       *ExistingTable,
    ACPI_TABLE_HEADER       **NewTable)
{
    if (!ExistingTable || !NewTable) {
		return (AE_BAD_PARAMETER);
	}

	*NewTable = NULL;
	return (AE_OK);
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsPhysicalTableOverride
 *
 * PARAMETERS:  ExistingTable       - Header of current table (probably firmware)
 *              NewAddress          - Where new table address is returned
 *                                    (Physical address)
 *              NewTableLength      - Where new table length is returned
 *
 * RETURN:      Status, address/length of new table. Null pointer returned
 *              if no table is available to override.
 *
 * DESCRIPTION: Returns AE_SUPPORT.
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsPhysicalTableOverride (
    ACPI_TABLE_HEADER       *ExistingTable,
    ACPI_PHYSICAL_ADDRESS   *NewAddress,
    UINT32                  *NewTableLength)
{
    return (AE_NOT_IMPLEMENTED);
}

ACPI_STATUS
AcpiOsGetTableByName (
    char                    *Signature,
    UINT32                  Instance,
    ACPI_TABLE_HEADER       **Table,
    ACPI_PHYSICAL_ADDRESS   *Address)
{
    return (AE_NOT_IMPLEMENTED);
}

ACPI_STATUS
AcpiOsGetTableByIndex (
    UINT32                  Index,
    ACPI_TABLE_HEADER       **Table,
    UINT32                  *Instance,
    ACPI_PHYSICAL_ADDRESS   *Address)
{
    return (AE_NOT_IMPLEMENTED);
}

ACPI_STATUS
AcpiOsGetTableByAddress (
    ACPI_PHYSICAL_ADDRESS   Address,
    ACPI_TABLE_HEADER       **Table)
{
    return (AE_NOT_IMPLEMENTED);
}
