/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

#ifndef _SAMPLE_H_
#define _SAMPLE_H_ 1

#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)

#include <unistd.h>
#include <stdint.h>

#include "pkcs11.h"
#include "ep11.h"
#include "grep11.h"

#endif