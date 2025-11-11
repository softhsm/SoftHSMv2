/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 OSSLSLHUtils.cpp

 OpenSSL SLHDSA Utils
 *****************************************************************************/

#include "OSSLSLHUtil.h"
#include "log.h"
#include <string.h>

namespace OSSLSLH {

unsigned long getSignatureSizeFromName(const char* name)
{
    if (name == NULL){
        ERROR_MSG("Could not determine the signature size, name is NULL");
        return 0;
    }
    unsigned long name_len = strnlen(name, 100);
    unsigned long signature_size = 0;

    if (name_len < 4) {
        ERROR_MSG("Could not determine the signature size, name size is smaller than 4");
        return 0;
    }

    if (strncmp(&name[name_len - 4], "128s", 4) == 0) {
        signature_size = 7856;
    } else if (strncmp(&name[name_len - 4], "128f", 4) == 0) {
        signature_size = 17088;
    } else if (strncmp(&name[name_len - 4], "192s", 4) == 0) {
        signature_size = 16224;
    } else if (strncmp(&name[name_len - 4], "192f", 4) == 0) {
        signature_size = 35664;
    } else if (strncmp(&name[name_len - 4], "256s", 4) == 0) {
        signature_size = 29792;
    } else if (strncmp(&name[name_len - 4], "256f", 4) == 0) {
        signature_size = 49856;
    } else{
        ERROR_MSG("Could not determine the signature size, returned 0");
        return 0;
    }
	return signature_size;
}

} // namespace OSSLSLH
