/*
 * QEMU OpenTitan One Time Programmable (OTP) memory controller
 *
 * Copyright (c) 2023 Rivos, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef HW_OPENTITAN_OT_OTP_H
#define HW_OPENTITAN_OT_OTP_H

#include "qemu/osdep.h"
#include "qom/object.h"

#define TYPE_OT_OTP "ot-otp"
OBJECT_DECLARE_SIMPLE_TYPE(OtOTPState, OT_OTP)

/*
 * Provide OTP lifecycle information.
 *
 * @lc_state if not NULL, updated with the encoded LifeCycle state
 * @tcount if not NULL, updated with the LifeCycle transition count
 */
void ot_otp_ctrl_get_lc_info(OtOTPState *s, uint32_t *lc_state,
                             unsigned *tcount);

/*
 * Hardware configuration (for HW_CFG partition)
 */
typedef struct {
    uint32_t device_id[8u];
    uint32_t manuf_state[8u];
    /* the following values are stored as OT_MULTIBITBOOL8 */
    uint8_t en_sram_ifetch;
    uint8_t en_csrng_sw_app_read;
    uint8_t en_entropy_src_fw_read;
    uint8_t en_entropy_src_fw_over;
} OtOTPHWCfg;

/* Retrieve HW configuration partition data */
const OtOTPHWCfg *ot_otp_ctrl_get_hw_cfg(OtOTPState *s);

#endif /* HW_OPENTITAN_OT_OTP_H */
