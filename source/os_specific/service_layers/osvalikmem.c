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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#define __MODULE "ACPI-MEMORY"

#include <acpi.h>
#include <arch/acpi.h>
#include <memoryspace.h>
#include <debug.h>

/**
 * @brief Maps a physical ACPICA range using the architecture's memory policy.
 *
 * Memory initialization must have completed. ACPICA uses this entry point for
 * tables and SystemMemory operation regions, so it must not assume that every
 * request describes device registers. The architecture decides which ranges
 * it can safely map and supplies their cache attributes.
 */
void*
AcpiOsMapMemory(
    _In_ ACPI_PHYSICAL_ADDRESS physical,
    _In_ ACPI_SIZE             length)
{
    size_t       pageSize = GetMemorySpacePageSize();
    size_t       offset = (size_t)(physical % pageSize);
    size_t       mappedLength;
    unsigned int flags;
    vaddr_t      address;
    oserr_t      status;

    // Check both address and size arithmetic before narrowing to paddr_t or
    // rounding. On i386, ACPICA's 64-bit physical address can exceed what the
    // mapper represents. The entire final page must also be representable.
    if (!length || physical > (paddr_t)-1 || length - 1 > (paddr_t)-1 - physical) {
        return NULL;
    }

    if (length > SIZE_MAX - offset || length + offset > SIZE_MAX - (pageSize - 1)) {
        return NULL;
    }

    mappedLength = (length + offset + pageSize - 1) & ~(pageSize - 1);
    physical -= offset;
    if (mappedLength - 1 > (paddr_t)-1 - physical) {
        return NULL;
    }

    status = ArchAcpiGetMappingFlags(physical, mappedLength, &flags);
    if (status != OS_EOK) {
        return NULL;
    }

    // Use the domain's kernel space for both operations. Table references may
    // outlive the thread that requested them. PERSISTENT prevents unmapping a
    // table view from freeing physical pages supplied by firmware.
    status = MemorySpaceMap(
        GetDomainMemorySpace(),
        &(struct MemorySpaceMapOptions) {
            .PhysicalStart = (paddr_t)physical,
            .Length = mappedLength,
            .Flags = MAPPING_COMMIT | MAPPING_PERSISTENT | flags,
            .PlacementFlags = MAPPING_PHYSICAL_CONTIGUOUS | MAPPING_VIRTUAL_GLOBAL
        },
        &address
    );
    if (status != OS_EOK) {
        return NULL;
    }
    return (void*)(address + offset);
}

/**
 * @brief Removes one ACPICA mapping without releasing its physical pages.
 *
 * Address and length must be the exact pair returned to ACPICA by MapMemory.
 * Reconstruct the same page range, including the original physical offset.
 */
void
AcpiOsUnmapMemory(
    _In_ void*     logicalAddress,
    _In_ ACPI_SIZE length)
{
    size_t  pageSize = GetMemorySpacePageSize();
    vaddr_t address = (vaddr_t)logicalAddress;
    size_t  offset = address % pageSize;
    size_t  mappedLength;
    oserr_t status;

    if (!length || length > SIZE_MAX - offset || length + offset > SIZE_MAX - (pageSize - 1)) {
        return;
    }

    mappedLength = (length + offset + pageSize - 1) & ~(pageSize - 1);
    status = MemorySpaceUnmap(
        GetDomainMemorySpace(),
        address - offset,
        mappedLength
    );
    if (status != OS_EOK) {
        ERROR("Failed to unmap ACPICA memory at 0x%llx", (unsigned long long)address);
    }
}
