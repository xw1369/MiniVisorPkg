/** @file
  Null library instance for StackCheckLib which can be included
  when a build needs to include stack check functions but does
  not want to generate stack check failures.

  Copyright (c) Microsoft Corporation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Base.h>

/**
  This function is called when a stack cookie check fails.
  This function should not return.
**/
VOID
EFIAPI
__report_rangecheckfailure (
  VOID
  )
{
  // Do nothing - this is a null implementation
}

/**
  This function is called when a GS handler check fails.
  This function should not return.
**/
VOID
EFIAPI
__GSHandlerCheck (
  VOID
  )
{
  // Do nothing - this is a null implementation
}

/**
  This function is called when a security check cookie fails.
  This function should not return.
**/
VOID
EFIAPI
__security_check_cookie (
  VOID
  )
{
  // Do nothing - this is a null implementation
}
