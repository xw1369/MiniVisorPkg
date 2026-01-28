#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiDriverEntryPoint.h>

EFI_STATUS
EFIAPI
MiniVisorHypervisorEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  Print(L"MiniVisor Hypervisor v1.0\n");
  return EFI_SUCCESS;
}
