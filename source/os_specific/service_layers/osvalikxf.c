/**
 * MollenOS
 *
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
 * ACPICA Support Layer (System Functions)
 *  - Missing implementations are todo
 */
#define __MODULE "ACPI"
//#define __TRACE

/* Includes
 * - (OS) System */
#include <arch/thread.h>
#include <arch/utils.h>
#include <arch/time.h>
#include <arch/io.h>
#include <semaphore.h>
#include <memoryspace.h>
#include <interrupts.h>
#include <threading.h>
#include <scheduler.h>
#include <timers.h>
#include <debug.h>
#include <heap.h>

/* Includes
 * - (ACPI) System */
#include <acpi.h>
#include <accommon.h>

/* Definitions
 * - Component Setup */
#define _COMPONENT ACPI_OS_SERVICES
ACPI_MODULE_NAME("vali_kernel_interface")

#define MAX_NUMBER_ACPI_INTS 4

static struct AcpiInterruptProxy {
    UUId_t           Id;
    ACPI_OSD_HANDLER Handler;
    void*            Context;
}             AcpiGbl_Interrupts[MAX_NUMBER_ACPI_INTS] = { { 0 } };
static char   AcpiGbl_OutputBuffer[512]                = { 0 };
static int    AcpiGbl_OutputIndex                      = 0;
static void*  AcpiGbl_RedirectionTarget                = NULL;

static Semaphore_t            Semaphores[ACPI_OS_MAX_SEMAPHORES]          = { { 0 } };
static ACPI_OS_SEMAPHORE_INFO AcpiGbl_Semaphores[ACPI_OS_MAX_SEMAPHORES]  = { { 0 } };
static int                    AcpiGbl_DebugTimeout                        = 0;

static InterruptStatus_t
AcpiInterruptEntry(
    _In_ FastInterruptResources_t* ResourceTable,
    _In_ void*                     Context)
{
    struct AcpiInterruptProxy* Proxy = (struct AcpiInterruptProxy*)Context;
    _CRT_UNUSED(ResourceTable);
    
    if (Proxy->Handler(Proxy->Context) != ACPI_INTERRUPT_HANDLED) {
        return InterruptNotHandled;
    }
    return InterruptHandled; 
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsInitialize
 *
 * PARAMETERS:  None
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Initialize the OSL
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsInitialize (
    void)
{
    return AE_OK;
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsTerminate
 *
 * PARAMETERS:  None
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Nothing to do for MollenOS
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsTerminate (
    void)
{
    // Do cleanup, but not really as this only happens
    // on system shutdown
    return AE_OK;
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsInstallInterruptHandler
 *
 * PARAMETERS:  InterruptNumber     - Level handler should respond to.
 *              ServiceRoutine      - Address of the ACPI interrupt handler
 *              Context             - User context
 *
 * RETURN:      Handle to the newly installed handler.
 *
 * DESCRIPTION: Install an interrupt handler. Used to install the ACPI
 *              OS-independent handler.
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsInstallInterruptHandler (
    UINT32                  InterruptNumber,
    ACPI_OSD_HANDLER        ServiceRoutine,
    void                    *Context)
{
    DeviceInterrupt_t ACPIInterrupt;
    int               i;
    TRACE("AcpiOsInstallInterruptHandler(0x%" PRIxIN ", 0x%" PRIxIN ")",
        ServiceRoutine, Context);

    // Sanitize param
    if (InterruptNumber >= 32) {
        return AE_ERROR;
    }
    
    for (i = 0; i < MAX_NUMBER_ACPI_INTS; i++) {
        if (AcpiGbl_Interrupts[i].Handler == NULL) {
            memset(&ACPIInterrupt, 0, sizeof(DeviceInterrupt_t));
            ACPIInterrupt.FastInterrupt.Handler = (InterruptHandler_t)AcpiInterruptEntry;
        	ACPIInterrupt.Context               = &AcpiGbl_Interrupts[i];
        	ACPIInterrupt.Line                  = InterruptNumber;
        	ACPIInterrupt.Pin                   = INTERRUPT_NONE;
        	ACPIInterrupt.Vectors[0]            = InterruptNumber;
        	ACPIInterrupt.Vectors[1]            = INTERRUPT_NONE;
        
            AcpiGbl_Interrupts[i].Id = InterruptRegister(&ACPIInterrupt, INTERRUPT_KERNEL);
            if (AcpiGbl_Interrupts[i].Id != UUID_INVALID) {
                AcpiGbl_Interrupts[i].Handler = ServiceRoutine;
                AcpiGbl_Interrupts[i].Context = Context;
                return AE_OK;
            }
        }
    }
	return AE_ERROR;
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsRemoveInterruptHandler
 *
 * PARAMETERS:  Handle              - Returned when handler was installed
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Uninstalls an interrupt handler.
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsRemoveInterruptHandler (
    UINT32                  InterruptNumber,
    ACPI_OSD_HANDLER        ServiceRoutine)
{
    int i;
    
    for (i = 0; i < MAX_NUMBER_ACPI_INTS; i++) {
        if (AcpiGbl_Interrupts[i].Handler == ServiceRoutine &&
            AcpiGbl_Interrupts[i].Context == (void*)(size_t)InterruptNumber) {
            if (InterruptUnregister(AcpiGbl_Interrupts[i].Id) != OsSuccess) {
                return AE_ERROR;
            }
            AcpiGbl_Interrupts[i].Handler = NULL;
            AcpiGbl_Interrupts[i].Context = NULL;
            return AE_OK;
        }
    }
    return AE_ERROR;
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsGetThreadId
 *
 * PARAMETERS:  None
 *
 * RETURN:      Id of the running thread
 *
 * DESCRIPTION: Get the Id of the current (running) thread
 *
 *****************************************************************************/
ACPI_THREAD_ID
AcpiOsGetThreadId (
    void)
{
    return (ACPI_THREAD_ID)GetCurrentThreadId() + 1;
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsExecute
 *
 * PARAMETERS:  Type                - Type of execution
 *              Function            - Address of the function to execute
 *              Context             - Passed as a parameter to the function
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Execute a new thread
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsExecute (
    ACPI_EXECUTE_TYPE       Type,
    ACPI_OSD_EXEC_CALLBACK  Function,
    void                    *Context)
{
    UUId_t     Id;
    OsStatus_t Status = CreateThread("acpi-worker", Function, Context, 0, UUID_INVALID, &Id);
    if (Status != OsSuccess) {
        return AE_OK;
    }
    return AE_ERROR;
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsWaitEventsComplete
 *
 * PARAMETERS:  None
 *
 * RETURN:      None
 *
 * DESCRIPTION: Wait for all asynchronous events to complete.
 *
 *****************************************************************************/
void
AcpiOsWaitEventsComplete (
    void)
{
    // Do nothing
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsSleep
 *
 * PARAMETERS:  Milliseconds        - Time to sleep
 *
 * RETURN:      None. Blocks until sleep is completed.
 *
 * DESCRIPTION: Sleep at millisecond granularity
 *
 *****************************************************************************/
void
AcpiOsSleep (
    UINT64 Milliseconds)
{
    if (GetCurrentThreadForCore(ArchGetProcessorCoreId()) != NULL) {
        SchedulerSleep((size_t)Milliseconds);
    }
    else {
        AcpiOsStall(Milliseconds * 1000);
    }
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsStall
 *
 * PARAMETERS:  Microseconds        - Time to stall
 *
 * RETURN:      None. Blocks until stall is completed.
 *
 * DESCRIPTION: Sleep at microsecond granularity (1 Milli = 1000 Micro)
 *
 *****************************************************************************/
void
AcpiOsStall (
    UINT32                  Microseconds)
{
    // We never stall for less than 1 ms
    ArchStallProcessorCore((Microseconds / 1000) + 1);
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsEnterSleep
 *
 * PARAMETERS:  SleepState          - Which sleep state to enter
 *              RegaValue           - Register A value
 *              RegbValue           - Register B value
 *
 * RETURN:      Status
 *
 * DESCRIPTION: A hook before writing sleep registers to enter the sleep
 *              state. Return AE_CTRL_SKIP to skip further sleep register
 *              writes.
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsEnterSleep (
    UINT8  SleepState,
    UINT32 RegaValue,
    UINT32 RegbValue)
{
    // Not used at this moment
    return AE_OK;
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsSignal
 *
 * PARAMETERS:  Function            - ACPICA signal function code
 *              Info                - Pointer to function-dependent structure
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Miscellaneous functions.
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsSignal (
    UINT32                  Function,
    void                    *Info)
{
    FATAL(FATAL_SCOPE_KERNEL, "AcpiOsSignal()");
    return AE_ERROR;
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsReadable
 *
 * PARAMETERS:  Pointer             - Area to be verified
 *              Length              - Size of area
 *
 * RETURN:      TRUE if readable for entire length
 *
 * DESCRIPTION: Verify that a pointer is valid for reading
 *
 *****************************************************************************/
BOOLEAN
AcpiOsReadable (
    void                    *Pointer,
    ACPI_SIZE               Length)
{
    FATAL(FATAL_SCOPE_KERNEL, "AcpiOsReadable()");
    return FALSE;
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsWritable
 *
 * PARAMETERS:  Pointer             - Area to be verified
 *              Length              - Size of area
 *
 * RETURN:      TRUE if writable for entire length
 *
 * DESCRIPTION: Verify that a pointer is valid for writing
 *
 *****************************************************************************/
BOOLEAN
AcpiOsWritable (
    void                    *Pointer,
    ACPI_SIZE               Length)
{
    FATAL(FATAL_SCOPE_KERNEL, "AcpiOsWritable()");
    return FALSE;
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsGetTimer
 *
 * PARAMETERS:  None
 *
 * RETURN:      Current ticks in 100-nanosecond units
 *
 * DESCRIPTION: Get the value of a system timer
 *
 ******************************************************************************/
UINT64
AcpiOsGetTimer (
    void)
{
    UINT64 CurrentTime = 0;
    TimersGetSystemTick((clock_t*)&CurrentTime);
    return CurrentTime;
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsAllocate
 *
 * PARAMETERS:  Size                - Amount to allocate, in bytes
 *
 * RETURN:      Pointer to the new allocation. Null on error.
 *
 * DESCRIPTION: Allocate memory. Algorithm is dependent on the OS.
 *
 *****************************************************************************/
void *
AcpiOsAllocate(
    ACPI_SIZE               Size)
{
    return kmalloc((size_t)Size);
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsFree
 *
 * PARAMETERS:  Mem                 - Pointer to previously allocated memory
 *
 * RETURN:      None.
 *
 * DESCRIPTION: Free memory allocated via AcpiOsAllocate
 *
 *****************************************************************************/
void
AcpiOsFree(
    void *                  Memory)
{
    kfree(Memory);
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsMapMemory
 *
 * PARAMETERS:  Where               - Physical address of memory to be mapped
 *              Length              - How much memory to map
 *
 * RETURN:      Pointer to mapped memory. Null on error.
 *
 * DESCRIPTION: Map physical memory into caller's address space
 *
 *****************************************************************************/
void *
AcpiOsMapMemory(
    ACPI_PHYSICAL_ADDRESS   Where,
    ACPI_SIZE               Length)
{
    PhysicalAddress_t Physical       = (PhysicalAddress_t)Where;
    size_t            Offset         = (size_t)(Where % GetMemorySpacePageSize());
    size_t            AdjustedLength = Length + Offset;
    VirtualAddress_t  Result         = 0;

    // We have everything below 4mb identity mapped
    if (Physical >= 0x1000 && Physical < 0x400000) {
        return (void*)Physical;
    }
    if (CreateMemorySpaceMapping(GetCurrentMemorySpace(), &Result, &Physical, 
        AdjustedLength, MAPPING_COMMIT | MAPPING_NOCACHE | MAPPING_PERSISTENT | MAPPING_READONLY,
        MAPPING_PHYSICAL_CONTIGIOUS | MAPPING_VIRTUAL_GLOBAL, __MASK) != OsSuccess) {
        // Uhh
        ERROR("Failed to map physical memory 0x%x", Where);
        return NULL;
    }
    return (void*)(Result + Offset);
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsUnmapMemory
 *
 * PARAMETERS:  Where               - Logical address of memory to be unmapped
 *              Length              - How much memory to unmap
 *
 * RETURN:      None.
 *
 * DESCRIPTION: Delete a previously created mapping. Where and Length must
 *              correspond to a previous mapping exactly.
 *
 *****************************************************************************/
void
AcpiOsUnmapMemory(
    void*                   LogicalAddress,
    ACPI_SIZE               Size)
{
    VirtualAddress_t Address        = (VirtualAddress_t)LogicalAddress;
    size_t           Offset         = Address % GetMemorySpacePageSize();
    size_t           AdjustedLength = Size + Offset;

    // We have everything below 4mb identity mapped
    if (Address >= 0x1000 && Address < 0x400000) {
        return;
    }
    else {
        if (RemoveMemorySpaceMapping(GetCurrentMemorySpace(), Address - Offset, AdjustedLength) != OsSuccess) {
            ERROR("Failed to unmap memory 0x%x", Address);   
        }
    }
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsGetPhysicalAddress
 *
 * PARAMETERS:  LogicalAddress      - Logical address to lookup
 *              PhysicalAddress     - Where to store the result
 *
 * RETURN:      Status Code.
 *
 * DESCRIPTION: Retrieve the physical address of a logical address. Replaces the value.
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsGetPhysicalAddress(
    void                    *LogicalAddress,
    ACPI_PHYSICAL_ADDRESS   *PhysicalAddress)
{
    VirtualAddress_t  Address = (VirtualAddress_t)LogicalAddress;
    PhysicalAddress_t Result;
    
    if (GetMemorySpaceMapping(GetCurrentMemorySpace(), Address, 1, &Result) != OsSuccess) {
        return AE_ERROR;
    }
    *PhysicalAddress = (ACPI_PHYSICAL_ADDRESS)Result;
    return AE_OK;
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsReadPort
 *
 * PARAMETERS:  Address             - Address of I/O port/register to read
 *              Value               - Where value is placed
 *              Width               - Number of bits
 *
 * RETURN:      Value read from port
 *
 * DESCRIPTION: Read data from an I/O port or register
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsReadPort (
    ACPI_IO_ADDRESS         Address,
    UINT32                  *Value,
    UINT32                  Width)
{
    ACPI_FUNCTION_NAME(OsReadPort);
    size_t LargeValue;
    if (ReadDirectIo(DeviceIoPortBased, Address, DIVUP(Width, 8), &LargeValue) != OsSuccess) {
        ACPI_ERROR((AE_INFO, "Bad width parameter: %X", Width));
        return (AE_BAD_PARAMETER);
    }
    *Value = LODWORD(LargeValue);
    return (AE_OK);
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsWritePort
 *
 * PARAMETERS:  Address             - Address of I/O port/register to write
 *              Value               - Value to write
 *              Width               - Number of bits
 *
 * RETURN:      None
 *
 * DESCRIPTION: Write data to an I/O port or register
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsWritePort (
    ACPI_IO_ADDRESS         Address,
    UINT32                  Value,
    UINT32                  Width)
{
    ACPI_FUNCTION_NAME(OsWritePort);
    size_t OutValue = (size_t)(Value & 0xFFFFFFFF);
    if (WriteDirectIo(DeviceIoPortBased, Address, DIVUP(Width, 8), OutValue) != OsSuccess) {
        ACPI_ERROR((AE_INFO, "Bad width parameter: %X", Width));
        return (AE_BAD_PARAMETER);
    }
    return (AE_OK);
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsReadMemory
 *
 * PARAMETERS:  Address             - Physical Memory Address to read
 *              Value               - Where value is placed
 *              Width               - Number of bits (8,16,32, or 64)
 *
 * RETURN:      Value read from physical memory address. Always returned
 *              as a 64-bit integer, regardless of the read width.
 *
 * DESCRIPTION: Read data from a physical memory address
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsReadMemory (
    ACPI_PHYSICAL_ADDRESS   Address,
    UINT64                  *Value,
    UINT32                  Width)
{
    ACPI_FUNCTION_NAME(AcpiOsReadMemory);
    size_t InputValue;
    if (ReadDirectIo(DeviceIoMemoryBased, Address, DIVUP(Width, 8), &InputValue) != OsSuccess) {
        ACPI_ERROR((AE_INFO, "Bad width parameter: %X", Width));
        return (AE_BAD_PARAMETER);
    }
    *Value = (UINT64)InputValue;
    return (AE_OK);
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsWriteMemory
 *
 * PARAMETERS:  Address             - Physical Memory Address to write
 *              Value               - Value to write
 *              Width               - Number of bits (8,16,32, or 64)
 *
 * RETURN:      None
 *
 * DESCRIPTION: Write data to a physical memory address
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsWriteMemory (
    ACPI_PHYSICAL_ADDRESS   Address,
    UINT64                  Value,
    UINT32                  Width)
{
    ACPI_FUNCTION_NAME(AcpiOsWriteMemory);
    size_t OutValue = (size_t)Value;
    if (WriteDirectIo(DeviceIoMemoryBased, Address, DIVUP(Width, 8), OutValue) != OsSuccess) {
        ACPI_ERROR((AE_INFO, "Bad width parameter: %X", Width));
        return (AE_BAD_PARAMETER);
    }
    return (AE_OK);
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsReadPciConfiguration
 *
 * PARAMETERS:  PciId               - Seg/Bus/Dev
 *              Register            - Device Register
 *              Value               - Buffer where value is placed
 *              Width               - Number of bits
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Read data from PCI configuration space
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsReadPciConfiguration (
    ACPI_PCI_ID             *PciId,
    UINT32                  Reg,
    UINT64                  *Value,
    UINT32                  Width)
{
    ACPI_FUNCTION_NAME(AcpiOsReadPciConfiguration);
    size_t InputValue;
    if (ReadDirectPci(PciId->Bus, PciId->Device, PciId->Function, Reg, DIVUP(Width, 8), &InputValue) != OsSuccess) {
        ACPI_ERROR((AE_INFO, "Bad width parameter: %X", Width));
        return (AE_BAD_PARAMETER);
    }
    *Value = (UINT64)InputValue;
    return (AE_OK);
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsWritePciConfiguration
 *
 * PARAMETERS:  PciId               - Seg/Bus/Dev
 *              Register            - Device Register
 *              Value               - Value to be written
 *              Width               - Number of bits
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Write data to PCI configuration space
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsWritePciConfiguration (
    ACPI_PCI_ID             *PciId,
    UINT32                  Reg,
    UINT64                  Value,
    UINT32                  Width)
{
    ACPI_FUNCTION_NAME(AcpiOsWritePciConfiguration);
    size_t OutValue = (size_t)Value;
    if (WriteDirectPci(PciId->Bus, PciId->Device, PciId->Function, Reg, DIVUP(Width, 8), OutValue) != OsSuccess) {
        ACPI_ERROR((AE_INFO, "Bad width parameter: %X", Width));
        return (AE_BAD_PARAMETER);
    }
    return (AE_OK);
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsPrintf
 *
 * PARAMETERS:  Fmt, ...            - Standard printf format
 *
 * RETURN:      None
 *
 * DESCRIPTION: Formatted output
 *
 *****************************************************************************/
void ACPI_INTERNAL_VAR_XFACE
AcpiOsPrintf (
    const char              *Format,
    ...)
{
    va_list	Args;
	va_start(Args, Format);
	AcpiOsVprintf(Format, Args);
	va_end(Args);
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsVprintf
 *
 * PARAMETERS:  Fmt                 - Standard printf format
 *              Args                - Argument list
 *
 * RETURN:      None
 *
 * DESCRIPTION: Formatted output with argument list pointer
 *
 *****************************************************************************/
void
AcpiOsVprintf (
    const char              *Format,
    va_list                 Args)
{
    char Buffer[256] = { 0 };
    int  i           = 0;
    vsprintf(Buffer, Format, Args);
    
    while (Buffer[i]) {
        if (AcpiGbl_OutputIndex == sizeof(AcpiGbl_OutputBuffer) || Buffer[i] == '\n') {
            WRITELINE(&AcpiGbl_OutputBuffer[0]);
            memset(&AcpiGbl_OutputBuffer[0], 0, sizeof(AcpiGbl_OutputBuffer));
            AcpiGbl_OutputIndex = 0;
            if (Buffer[i] == '\n') {
                i++;
            }
            continue;
        }
        AcpiGbl_OutputBuffer[AcpiGbl_OutputIndex++] = Buffer[i++];
    }
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsRedirectOutput
 *
 * PARAMETERS:  Destination         - An open file handle/pointer
 *
 * RETURN:      None
 *
 * DESCRIPTION: Causes redirect of AcpiOsPrintf and AcpiOsVprintf
 *
 *****************************************************************************/
void
AcpiOsRedirectOutput (
    void *Destination)
{
    AcpiGbl_RedirectionTarget = Destination;
}

/******************************************************************************
 *
 * FUNCTION:    Spinlock interfaces
 *
 * DESCRIPTION: Map these interfaces to one-valued semaphore interfaces
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsCreateLock(
    ACPI_SPINLOCK* OutHandle)
{
    return AcpiOsCreateSemaphore(1, 1, OutHandle);
}

void
AcpiOsDeleteLock(
    ACPI_SPINLOCK Handle)
{
    AcpiOsDeleteSemaphore(Handle);
}

ACPI_CPU_FLAGS
AcpiOsAcquireLock(
    ACPI_SPINLOCK Handle)
{
    AcpiOsWaitSemaphore(Handle, 1, 0);
    return 0;
}

void
AcpiOsReleaseLock(
    ACPI_SPINLOCK  Handle,
    ACPI_CPU_FLAGS Flags)
{
    AcpiOsSignalSemaphore(Handle, 1);
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsCreateSemaphore
 *
 * PARAMETERS:  MaxUnits            - Maximum units that can be sent
 *              InitialUnits        - Units to be assigned to the new semaphore
 *              OutHandle           - Where a handle will be returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Create an OS semaphore
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsCreateSemaphore(
    UINT32                  MaxUnits,
    UINT32                  InitialUnits,
    ACPI_SEMAPHORE          *OutHandle)
{
    // Variables
    size_t i = 0;
    ACPI_FUNCTION_NAME(OsCreateSemaphore);

    if (MaxUnits == ACPI_UINT32_MAX) {
        MaxUnits = 255;
    }

    if (InitialUnits == ACPI_UINT32_MAX) {
        InitialUnits = MaxUnits;
    }

    if (InitialUnits > MaxUnits) {
        return (AE_BAD_PARAMETER);
    }

    // Find an empty slot
    for (i = 0; i < ACPI_OS_MAX_SEMAPHORES; i++) {
        if (!AcpiGbl_Semaphores[i].OsHandle) {
            break;
        }
    }
    if (i >= ACPI_OS_MAX_SEMAPHORES) {
        ACPI_EXCEPTION ((AE_INFO, AE_LIMIT,
            "Reached max semaphores (%u), could not create",
            ACPI_OS_MAX_SEMAPHORES));
        return (AE_LIMIT);
    }

    // Initialize the semaphore
    SemaphoreConstruct(&Semaphores[i], InitialUnits, MaxUnits);
    AcpiGbl_Semaphores[i].MaxUnits      = (uint16_t) MaxUnits;
    AcpiGbl_Semaphores[i].CurrentUnits  = (uint16_t) InitialUnits;
    AcpiGbl_Semaphores[i].OsHandle      = &Semaphores[i];

    TRACE("Handle=%u, Max=%u, Current=%u, OsHandle=%p\n",
        i, MaxUnits, InitialUnits, Semaphore);
    *OutHandle = (ACPI_SEMAPHORE)i;
    return (AE_OK);
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsDeleteSemaphore
 *
 * PARAMETERS:  Handle              - Handle returned by AcpiOsCreateSemaphore
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Delete an OS semaphore
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsDeleteSemaphore(
    ACPI_SEMAPHORE Handle)
{
    UINT32 Index = (UINT32) Handle;
    if ((Index >= ACPI_OS_MAX_SEMAPHORES) || !AcpiGbl_Semaphores[Index].OsHandle) {
        return (AE_BAD_PARAMETER);
    }
    AcpiGbl_Semaphores[Index].OsHandle = NULL;
    return (AE_OK);
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsWaitSemaphore
 *
 * PARAMETERS:  Handle              - Handle returned by AcpiOsCreateSemaphore
 *              Units               - How many units to wait for
 *              Timeout             - How long to wait
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Wait for units
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsWaitSemaphore(
    ACPI_SEMAPHORE          Handle,
    UINT32                  Units,
    UINT16                  Timeout)
{
    UINT32     Index = (UINT32) Handle;
    UINT32     Msecs = Timeout;
    OsStatus_t WaitStatus;
    ACPI_FUNCTION_ENTRY ();

    if ((Index >= ACPI_OS_MAX_SEMAPHORES) || !AcpiGbl_Semaphores[Index].OsHandle) {
        return (AE_BAD_PARAMETER);
    }

    if (Units > 1) {
        ERROR("WaitSemaphore: Attempt to receive %u units\n", Units);
        return (AE_NOT_IMPLEMENTED);
    }

    if (Timeout == ACPI_WAIT_FOREVER) {
        Msecs = 0;
        if (AcpiGbl_DebugTimeout) {
            // The debug timeout will prevent hang conditions
            Msecs = ACPI_OS_DEBUG_TIMEOUT;
        }
    }
    else {
        // Add 10ms to account for clock tick granularity
        Msecs += 10;
    }

    WaitStatus = SemaphoreWait(
        (Semaphore_t*)AcpiGbl_Semaphores[Index].OsHandle, 
        Msecs);
    if (WaitStatus == OsTimeout) {
        if (AcpiGbl_DebugTimeout) {
            ACPI_EXCEPTION ((AE_INFO, AE_TIME,
                "Debug timeout on semaphore 0x%04X (%ums)\n",
                Index, ACPI_OS_DEBUG_TIMEOUT));
        }
        return (AE_TIME);
    }

    if (AcpiGbl_Semaphores[Index].CurrentUnits == 0) {
        ACPI_ERROR ((AE_INFO,
            "%s - No unit received. Timeout 0x%X, OS_Status 0x%X",
            "mutex" /* AcpiUtGetMutexName (Index) */, Timeout, WaitStatus));
        return (AE_OK);
    }

    AcpiGbl_Semaphores[Index].CurrentUnits -= Units;
    return (AE_OK);
}

/******************************************************************************
 *
 * FUNCTION:    AcpiOsSignalSemaphore
 *
 * PARAMETERS:  Handle              - Handle returned by AcpiOsCreateSemaphore
 *              Units               - Number of units to send
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Send units
 *
 *****************************************************************************/
ACPI_STATUS
AcpiOsSignalSemaphore(
    ACPI_SEMAPHORE          Handle,
    UINT32                  Units)
{
    UINT32 Index = (UINT32) Handle;
    ACPI_FUNCTION_ENTRY();

    if (Index >= ACPI_OS_MAX_SEMAPHORES) {
        ERROR("SignalSemaphore: Index/Handle out of range: %2.2X\n", Index);
        return (AE_BAD_PARAMETER);
    }

    if (!AcpiGbl_Semaphores[Index].OsHandle) {
        ERROR("SignalSemaphore: Null OS handle, Index %2.2X\n", Index);
        return (AE_BAD_PARAMETER);
    }

    if (Units > 1) {
        ERROR("SignalSemaphore: Attempt to signal %u units, Index %2.2X\n", Units, Index);
        return (AE_NOT_IMPLEMENTED);
    }

    if ((AcpiGbl_Semaphores[Index].CurrentUnits + 1) >
        AcpiGbl_Semaphores[Index].MaxUnits) {
        ACPI_ERROR ((AE_INFO,
            "Oversignalled semaphore[%u]! Current %u Max %u",
            Index, AcpiGbl_Semaphores[Index].CurrentUnits,
            AcpiGbl_Semaphores[Index].MaxUnits));
        return (AE_LIMIT);
    }

    AcpiGbl_Semaphores[Index].CurrentUnits++;
    SemaphoreSignal((Semaphore_t*)AcpiGbl_Semaphores[Index].OsHandle, (int)Units);
    return (AE_OK);
}

//////////////////////////////////////////////////////////////////////////
///////// UNUSED
#include <acdisasm.h>

ACPI_STATUS
AcpiOsInitializeDebugger (
    void)
{
    return AE_NOT_IMPLEMENTED;
}

void
AcpiOsTerminateDebugger (
    void)
{

}

ACPI_STATUS
AcpiOsWaitCommandReady (
    void)
{
    return AE_NOT_IMPLEMENTED;
}

ACPI_STATUS
AcpiOsNotifyCommandComplete (
    void)
{
    return AE_NOT_IMPLEMENTED;
}

void
AcpiOsTracePoint (
    ACPI_TRACE_EVENT_TYPE   Type,
    BOOLEAN                 Begin,
    UINT8                   *Aml,
    char                    *Pathname)
{

}

void
MpSaveGpioInfo(
ACPI_PARSE_OBJECT       *Op,
AML_RESOURCE            *Resource,
UINT32                  PinCount,
UINT16                  *PinList,
char                    *DeviceName)
{
    
}

void
MpSaveSerialInfo(
ACPI_PARSE_OBJECT       *Op,
AML_RESOURCE            *Resource,
char                    *DeviceName)
{

}
