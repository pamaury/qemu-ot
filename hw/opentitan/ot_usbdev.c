/*
 * QEMU OpenTitan USBDEV device
 *
 * Copyright (c) 2025 lowRISC contributors.
 *
 * Author(s):
 *  Amaury Pouly <amaury.pouly@lowrisc.org>
 *  Douglas Reis <doreis@lowrisc.org>
 *
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

/*
 * OpenTitan has a "zero-time" simulation model in
 * hw/ip/usbdev/dv/env/usbdev_bfm.sv. This driver makes references to this
 * behavioural model as "BFM".
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "chardev/char-fe.h"
#include "hw/opentitan/ot_alert.h"
#include "hw/opentitan/ot_usbdev.h"
#include "hw/qdev-properties-system.h"
#include "hw/qdev-properties.h"
#include "hw/registerfields.h"
#include "hw/riscv/ibex_common.h"
#include "hw/riscv/ibex_irq.h"
#include "trace.h"


#define USBDEV_PARAM_N_ENDPOINTS 12u
#define USBDEV_PARAM_NUM_ALERTS  1u
#define USBDEV_PARAM_REG_WIDTH   32u

/* NOLINTNEXTLINE(misc-redundant-expression) */
static_assert(USBDEV_PARAM_N_ENDPOINTS == 12u,
              "This driver only supports 12 endpoints");

/* clang-format off */
REG32(USBDEV_INTR_STATE, 0x0u)
    SHARED_FIELD(USBDEV_INTR_PKT_RECEIVED, 0u, 1u)
    SHARED_FIELD(USBDEV_INTR_PKT_SENT, 1u, 1u)
    SHARED_FIELD(USBDEV_INTR_DISCONNECTED, 2u, 1u)
    SHARED_FIELD(USBDEV_INTR_HOST_LOST, 3u, 1u)
    SHARED_FIELD(USBDEV_INTR_LINK_RESET, 4u, 1u)
    SHARED_FIELD(USBDEV_INTR_LINK_SUSPEND, 5u, 1u)
    SHARED_FIELD(USBDEV_INTR_LINK_RESUME, 6u, 1u)
    SHARED_FIELD(USBDEV_INTR_AV_OUT_EMPTY, 7u, 1u)
    SHARED_FIELD(USBDEV_INTR_RX_FULL, 8u, 1u)
    SHARED_FIELD(USBDEV_INTR_AV_OVERFLOW, 9u, 1u)
    SHARED_FIELD(USBDEV_INTR_LINK_IN_ERR, 10u, 1u)
    SHARED_FIELD(USBDEV_INTR_RX_CRC_ERR, 11u, 1u)
    SHARED_FIELD(USBDEV_INTR_RX_PID_ERR, 12u, 1u)
    SHARED_FIELD(USBDEV_INTR_RX_BITSTUFF_ERR, 13u, 1u)
    SHARED_FIELD(USBDEV_INTR_FRAME, 14u, 1u)
    SHARED_FIELD(USBDEV_INTR_POWERED, 15u, 1u)
    SHARED_FIELD(USBDEV_INTR_LINK_OUT_ERR, 16u, 1u)
    SHARED_FIELD(USBDEV_INTR_AV_SETUP_EMPTY, 17u, 1u)
REG32(USBDEV_INTR_ENABLE, 0x4u)
REG32(USBDEV_INTR_TEST, 0x8u)
REG32(ALERT_TEST, 0xcu)
    FIELD(ALERT_TEST, FATAL_FAULT, 0u, 1u)
REG32(USBCTRL, 0x10u)
    FIELD(USBCTRL, ENABLE, 0u, 1u)
    FIELD(USBCTRL, RESUME_LINK_ACTIVE, 1u, 1u)
    FIELD(USBCTRL, DEVICE_ADDRESS, 16u, 7u)
/*
 * The following registers use the same layout:
 * the i-th bit corresponds to endpoint i.
 */
REG32(EP_OUT_ENABLE, 0x14u)
REG32(EP_IN_ENABLE, 0x18u)
REG32(USBSTAT, 0x1cu)
    FIELD(USBSTAT, FRAME, 0u, 11u)
    FIELD(USBSTAT, HOST_LOST, 11u, 1u)
    FIELD(USBSTAT, LINK_STATE, 12u, 3u)
    FIELD(USBSTAT, SENSE, 15u, 1u)
    FIELD(USBSTAT, AV_OUT_DEPTH, 16u, 4u)
    FIELD(USBSTAT, AV_SETUP_DEPTH, 20u, 3u)
    FIELD(USBSTAT, AV_OUT_FULL, 23u, 1u)
    FIELD(USBSTAT, RX_DEPTH, 24u, 4u)
    FIELD(USBSTAT, AV_SETUP_FULL, 30u, 1u)
    FIELD(USBSTAT, RX_EMPTY, 31u, 1u)
REG32(AVOUTBUFFER, 0x20u)
    FIELD(AVOUTBUFFER, BUFFER, 0u, 5u)
REG32(AVSETUPBUFFER, 0x24u)
    FIELD(AVSETUPBUFFER, BUFFER, 0u, 5u)
REG32(RXFIFO, 0x28u)
    FIELD(RXFIFO, BUFFER, 0u, 5u)
    FIELD(RXFIFO, SIZE, 8u, 7u)
    FIELD(RXFIFO, SETUP, 19u, 1u)
    FIELD(RXFIFO, EP, 20u, 4u)
/*
 * The following registers use the same layout:
 * the i-th bit corresponds to endpoint i.
 */
REG32(RXENABLE_SETUP, 0x2cu)
REG32(RXENABLE_OUT, 0x30u)
REG32(SET_NAK_OUT, 0x34u)
REG32(IN_SENT, 0x38u)
REG32(OUT_STALL, 0x3cu)
REG32(IN_STALL, 0x40u)
/*
 * The following is a multi register with
 * USBDEV_PARAM_N_ENDPOINTS instances.
 */
REG32(CONFIGIN_0, 0x44u)
    SHARED_FIELD(CONFIGIN_BUFFER, 0u, 5u)
    SHARED_FIELD(CONFIGIN_SIZE, 8u, 7u)
    SHARED_FIELD(CONFIGIN_SENDING, 29u, 1u)
    SHARED_FIELD(CONFIGIN_PEND, 30u, 1u)
    SHARED_FIELD(CONFIGIN_RDY, 31u, 1u)
REG32(CONFIGIN_1, 0x48u)
REG32(CONFIGIN_2, 0x4cu)
REG32(CONFIGIN_3, 0x50u)
REG32(CONFIGIN_4, 0x54u)
REG32(CONFIGIN_5, 0x58u)
REG32(CONFIGIN_6, 0x5cu)
REG32(CONFIGIN_7, 0x60u)
REG32(CONFIGIN_8, 0x64u)
REG32(CONFIGIN_9, 0x68u)
REG32(CONFIGIN_10, 0x6cu)
REG32(CONFIGIN_11, 0x70u)
/*
 * The following registers use the same layout:
 * the i-th bit corresponds to endpoint i.
 */
REG32(OUT_ISO, 0x74u)
REG32(IN_ISO, 0x78u)
REG32(OUT_DATA_TOGGLE, 0x7cu)
    FIELD(OUT_DATA_TOGGLE, STATUS, 0u, USBDEV_PARAM_N_ENDPOINTS)
    FIELD(OUT_DATA_TOGGLE, MASK, 16u, USBDEV_PARAM_N_ENDPOINTS)
REG32(IN_DATA_TOGGLE, 0x80u)
    FIELD(IN_DATA_TOGGLE, STATUS, 0u, USBDEV_PARAM_N_ENDPOINTS)
    FIELD(IN_DATA_TOGGLE, MASK, 16u, USBDEV_PARAM_N_ENDPOINTS)
REG32(PHY_PINS_SENSE, 0x84u)
    FIELD(PHY_PINS_SENSE, RX_DP_I, 0u, 1u)
    FIELD(PHY_PINS_SENSE, RX_DN_I, 1u, 1u)
    FIELD(PHY_PINS_SENSE, RX_D_I, 2u, 1u)
    FIELD(PHY_PINS_SENSE, TX_DP_O, 8u, 1u)
    FIELD(PHY_PINS_SENSE, TX_DN_O, 9u, 1u)
    FIELD(PHY_PINS_SENSE, TX_D_O, 10u, 1u)
    FIELD(PHY_PINS_SENSE, TX_SE0_O, 11u, 1u)
    FIELD(PHY_PINS_SENSE, TX_OE_O, USBDEV_PARAM_N_ENDPOINTS, 1u)
    FIELD(PHY_PINS_SENSE, PWR_SENSE, 16u, 1u)
REG32(PHY_PINS_DRIVE, 0x88u)
    FIELD(PHY_PINS_DRIVE, DP_O, 0u, 1u)
    FIELD(PHY_PINS_DRIVE, DN_O, 1u, 1u)
    FIELD(PHY_PINS_DRIVE, D_O, 2u, 1u)
    FIELD(PHY_PINS_DRIVE, SE0_O, 3u, 1u)
    FIELD(PHY_PINS_DRIVE, OE_O, 4u, 1u)
    FIELD(PHY_PINS_DRIVE, RX_ENABLE_O, 5u, 1u)
    FIELD(PHY_PINS_DRIVE, DP_PULLUP_EN_O, 6u, 1u)
    FIELD(PHY_PINS_DRIVE, DN_PULLUP_EN_O, 7u, 1u)
    FIELD(PHY_PINS_DRIVE, EN, 16u, 1u)
REG32(PHY_CONFIG, 0x8cu)
    FIELD(PHY_CONFIG, USE_DIFF_RCVR, 0u, 1u)
    FIELD(PHY_CONFIG, TX_USE_D_SE0, 1u, 1u)
    FIELD(PHY_CONFIG, EOP_SINGLE_BIT, 2u, 1u)
    FIELD(PHY_CONFIG, PINFLIP, 5u, 1u)
    FIELD(PHY_CONFIG, USB_REF_DISABLE, 6u, 1u)
    FIELD(PHY_CONFIG, TX_OSC_TEST_MODE, 7u, 1u)
REG32(WAKE_CONTROL, 0x90u)
    FIELD(WAKE_CONTROL, SUSPEND_REQ, 0u, 1u)
    FIELD(WAKE_CONTROL, WAKE_ACK, 1u, 1u)
REG32(WAKE_EVENTS, 0x94u)
    FIELD(WAKE_EVENTS, MODULE_ACTIVE, 0u, 1u)
    FIELD(WAKE_EVENTS, DISCONNECTED, 8u, 1u)
    FIELD(WAKE_EVENTS, BUS_RESET, 9u, 1u)
    FIELD(WAKE_EVENTS, BUS_NOT_IDLE, 10u, 1u)
REG32(FIFO_CTRL, 0x98u)
    FIELD(FIFO_CTRL, AVOUT_RST, 0u, 1u)
    FIELD(FIFO_CTRL, AVSETUP_RST, 1u, 1u)
    FIELD(FIFO_CTRL, RX_RST, 2u, 1u)
REG32(COUNT_OUT, 0x9cu)
    FIELD(COUNT_OUT, COUNT, 0u, 8u)
    FIELD(COUNT_OUT, DATATOG_OUT, USBDEV_PARAM_N_ENDPOINTS, 1u)
    FIELD(COUNT_OUT, DROP_RX, 13u, 1u)
    FIELD(COUNT_OUT, DROP_AVOUT, 14u, 1u)
    FIELD(COUNT_OUT, IGN_AVSETUP, 15u, 1u)
    FIELD(COUNT_OUT, ENDPOINTS, 16u, USBDEV_PARAM_N_ENDPOINTS)
    FIELD(COUNT_OUT, RST, 31u, 1u)
REG32(COUNT_IN, 0xa0u)
    FIELD(COUNT_IN, COUNT, 0u, 8u)
    FIELD(COUNT_IN, NODATA, 13u, 1u)
    FIELD(COUNT_IN, NAK, 14u, 1u)
    FIELD(COUNT_IN, TIMEOUT, 15u, 1u)
    FIELD(COUNT_IN, ENDPOINTS, 16u, USBDEV_PARAM_N_ENDPOINTS)
    FIELD(COUNT_IN, RST, 31u, 1u)
REG32(COUNT_NODATA_IN, 0xa4u)
    FIELD(COUNT_NODATA_IN, COUNT, 0u, 8u)
    FIELD(COUNT_NODATA_IN, ENDPOINTS, 16u, USBDEV_PARAM_N_ENDPOINTS)
    FIELD(COUNT_NODATA_IN, RST, 31u, 1u)
REG32(COUNT_ERRORS, 0xa8u)
    FIELD(COUNT_ERRORS, COUNT, 0u, 8u)
    FIELD(COUNT_ERRORS, PID_INVALID, 27u, 1u)
    FIELD(COUNT_ERRORS, BITSTUFF, 28u, 1u)
    FIELD(COUNT_ERRORS, CRC16, 29u, 1u)
    FIELD(COUNT_ERRORS, CRC5, 30u, 1u)
    FIELD(COUNT_ERRORS, RST, 31u, 1u)
/* clang-format on */

#define R32_OFF(_r_) ((_r_) / sizeof(uint32_t))

#define R_LAST_REG       (R_COUNT_ERRORS)
#define REGS_COUNT       (R_LAST_REG + 1u)
#define USBDEV_REGS_SIZE (REGS_COUNT * sizeof(uint32_t))

#define USBDEV_INTR_NUM 18u

#define USBDEV_INTR_RW1C_MASK \
    (USBDEV_INTR_DISCONNECTED_MASK | USBDEV_INTR_HOST_LOST_MASK | \
     USBDEV_INTR_LINK_RESET_MASK | USBDEV_INTR_LINK_SUSPEND_MASK | \
     USBDEV_INTR_LINK_RESUME_MASK | USBDEV_INTR_AV_OVERFLOW_MASK | \
     USBDEV_INTR_LINK_IN_ERR_MASK | USBDEV_INTR_RX_CRC_ERR_MASK | \
     USBDEV_INTR_RX_PID_ERR_MASK | USBDEV_INTR_RX_BITSTUFF_ERR_MASK | \
     USBDEV_INTR_FRAME_MASK | USBDEV_INTR_POWERED_MASK | \
     USBDEV_INTR_LINK_OUT_ERR_MASK)

#define USBDEV_INTR_MASK \
    (USBDEV_INTR_RW1C_MASK | USBDEV_INTR_PKT_RECEIVED_MASK | \
     USBDEV_INTR_PKT_SENT_MASK | USBDEV_INTR_AV_OUT_EMPTY_MASK | \
     USBDEV_INTR_RX_FULL_MASK | USBDEV_INTR_AV_SETUP_EMPTY_MASK)

#define USBDEV_USBCTRL_R_MASK \
    (R_USBCTRL_ENABLE_MASK | R_USBCTRL_DEVICE_ADDRESS_MASK)

static_assert(USBDEV_INTR_MASK == (1u << USBDEV_INTR_NUM) - 1u,
              "Interrupt mask mismatch");

#define USBDEV_DEVICE_SIZE   0x1000u
#define USBDEV_REGS_OFFSET   0u
#define USBDEV_BUFFER_OFFSET 0x800u
#define USBDEV_BUFFER_SIZE   0x800u

/*
 * Link state: this is the register field value, which we also use to
 * track the state of the link in general.
 */
typedef enum {
    /* Link disconnected (no VBUS or no pull-up connected). */
    OT_USBDEV_LINK_STATE_DISCONNECTED = 0,
    /* Link powered and connected, but not reset yet. */
    OT_USBDEV_LINK_STATE_POWERED = 1,
    /* Link suspended (constant idle/J for > 3 ms), but not reset yet. */
    OT_USBDEV_LINK_STATE_POWERED_SUSP = 2,
    /* Link active. */
    OT_USBDEV_LINK_STATE_ACTIVE = 3,
    /*
     * Link suspended (constant idle for > 3 ms), was active before
     * becoming suspended.
     */
    OT_USBDEV_LINK_STATE_SUSPENDED = 4,
    /* Link active but no SOF has been received since the last reset. */
    OT_USBDEV_LINK_STATE_ACTIVE_NOSOF = 5,
    /*
     * Link resuming to an active state,
     * pending the end of resume signaling.
     */
    OT_USBDEV_LINK_STATE_RESUMING = 6,
    OT_USBDEV_LINK_STATE_COUNT,
} OtUsbdevLinkState;

#define LINK_STATE_ENTRY(_name) \
    [OT_USBDEV_LINK_STATE_##_name] = stringify(_name)

static const char *LINK_STATE_NAME[] = {
    /* clang-format off */
    LINK_STATE_ENTRY(DISCONNECTED),
    LINK_STATE_ENTRY(POWERED),
    LINK_STATE_ENTRY(POWERED_SUSP),
    LINK_STATE_ENTRY(ACTIVE),
    LINK_STATE_ENTRY(SUSPENDED),
    LINK_STATE_ENTRY(ACTIVE_NOSOF),
    LINK_STATE_ENTRY(RESUMING),
    /* clang-format on */
};
#undef LINK_STATE_ENTRY

#define LINK_STATE_NAME(_st_) \
    (((unsigned)(_st_)) < ARRAY_SIZE(LINK_STATE_NAME) ? \
         LINK_STATE_NAME[(_st_)] : \
         "?")

struct OtUsbdevClass {
    SysBusDeviceClass parent_class;
    ResettablePhases parent_phases;
};

/* Size of the communication buffer for the chardev. */
#define CMD_BUF_SIZE 32u

/* NOLINTNEXTLINE(misc-redundant-expression) */
static_assert(USBDEV_PARAM_NUM_ALERTS == 1u,
              "This only supports a single alert (fault)");

/*
 * USB server protocol
 *
 * The protocol is documented in docs/opentitan/usbdev.md
 */

typedef enum {
    OT_USBDEV_SERVER_CMD_INVALID,
    OT_USBDEV_SERVER_CMD_HELLO,
    OT_USBDEV_SERVER_CMD_VBUS_ON,
    OT_USBDEV_SERVER_CMD_VBUS_OFF,
    OT_USBDEV_SERVER_CMD_CONNECT,
    OT_USBDEV_SERVER_CMD_DISCONNECT,
    OT_USBDEV_SERVER_CMD_RESET,
    OT_USBDEV_SERVER_CMD_RESUME,
    OT_USBDEV_SERVER_CMD_SUSPEND,
} OtUsbdevServerCmd;

typedef struct {
    uint32_t cmd; /* Command, see OtUsbdevServerCmd */
    uint32_t size; /* Size, excluding header */
    uint32_t id; /* Unique ID */
} OtUsbdevServerPktHdr;

#define OT_USBDEV_SERVER_HELLO_MAGIC "UDCX"
#define OT_USBDEV_SERVER_MAJOR_VER   1u
#define OT_USBDEV_SERVER_MINOR_VER   0u

typedef struct {
    char magic[4];
    uint16_t major_version;
    uint16_t minor_version;
} OtUsbdevServerHelloPkt;

/* State machine for the server receive path */
typedef enum {
    /* Wait for packet header */
    OT_USBDEV_SERVER_RECV_WAIT_HEADER,
    OT_USBDEV_SERVER_RECV_WAIT_DATA,
} OtUsbdevServerRecvState;

typedef struct {
    /* Current state of the receiver */
    OtUsbdevServerRecvState recv_state;
    size_t recv_rem; /* Remaining quantity to receive */
    uint8_t *recv_buf; /* Pointer to buffer where to receive */
    /* Packet header under reception or processing */
    OtUsbdevServerPktHdr recv_pkt;
    /* Packet data under reception or processing */
    uint8_t *recv_data;

    /* Current state of server */
    bool client_connected; /* We have a client */
    bool vbus_connected; /* The host has turned on VBUS */
    bool hello_done; /* Have received a HELLO? */
} OtUsbdevServer;

struct OtUsbdevState {
    SysBusDevice parent_obj;
    struct {
        MemoryRegion main;
        MemoryRegion regs;
        MemoryRegion buffer;
    } mmio;
    IbexIRQ irqs[USBDEV_INTR_NUM];
    IbexIRQ alert;

    /* Register content */
    uint32_t regs[REGS_COUNT];
    /* VBUS gate: meaning depends on the vbus_override mode */
    bool vbus_gate;

    /* Buffer content */
    uint32_t buffer[USBDEV_BUFFER_SIZE / sizeof(uint32_t)];

    /* Communication device and buffer for management. */
    CharBackend cmd_chr;
    char cmd_buf[CMD_BUF_SIZE];
    unsigned cmd_buf_pos;
    /* Communication device for the USB protocol. */
    CharBackend usb_chr;
    OtUsbdevServer usb_server;

    char *ot_id;
    /* Link to the clkmgr. */
    DeviceState *clock_src;
    /* Name of the USB clock. */
    char *usbclk_name;
    /* Name of the AON clock. */
    char *aonclk_name;
    /* VBUS override mode. */
    bool vbus_override;
};

#define REG_NAME(_reg_) \
    ((((_reg_) <= REGS_COUNT) && REG_NAMES[_reg_]) ? REG_NAMES[_reg_] : "?")

#define REG_NAME_ENTRY(_reg_) [R_##_reg_] = stringify(_reg_)
static const char *REG_NAMES[REGS_COUNT] = {
    /* clang-format off */
    REG_NAME_ENTRY(USBDEV_INTR_STATE),
    REG_NAME_ENTRY(USBDEV_INTR_ENABLE),
    REG_NAME_ENTRY(USBDEV_INTR_TEST),
    REG_NAME_ENTRY(ALERT_TEST),
    REG_NAME_ENTRY(USBCTRL),
    REG_NAME_ENTRY(EP_OUT_ENABLE),
    REG_NAME_ENTRY(EP_IN_ENABLE),
    REG_NAME_ENTRY(USBSTAT),
    REG_NAME_ENTRY(AVOUTBUFFER),
    REG_NAME_ENTRY(AVSETUPBUFFER),
    REG_NAME_ENTRY(RXFIFO),
    REG_NAME_ENTRY(RXENABLE_SETUP),
    REG_NAME_ENTRY(RXENABLE_OUT),
    REG_NAME_ENTRY(SET_NAK_OUT),
    REG_NAME_ENTRY(IN_SENT),
    REG_NAME_ENTRY(OUT_STALL),
    REG_NAME_ENTRY(IN_STALL),
    REG_NAME_ENTRY(CONFIGIN_0),
    REG_NAME_ENTRY(CONFIGIN_1),
    REG_NAME_ENTRY(CONFIGIN_2),
    REG_NAME_ENTRY(CONFIGIN_3),
    REG_NAME_ENTRY(CONFIGIN_4),
    REG_NAME_ENTRY(CONFIGIN_5),
    REG_NAME_ENTRY(CONFIGIN_6),
    REG_NAME_ENTRY(CONFIGIN_7),
    REG_NAME_ENTRY(CONFIGIN_8),
    REG_NAME_ENTRY(CONFIGIN_9),
    REG_NAME_ENTRY(CONFIGIN_10),
    REG_NAME_ENTRY(CONFIGIN_11),
    REG_NAME_ENTRY(OUT_ISO),
    REG_NAME_ENTRY(IN_ISO),
    REG_NAME_ENTRY(OUT_DATA_TOGGLE),
    REG_NAME_ENTRY(IN_DATA_TOGGLE),
    REG_NAME_ENTRY(PHY_PINS_SENSE),
    REG_NAME_ENTRY(PHY_PINS_DRIVE),
    REG_NAME_ENTRY(PHY_CONFIG),
    REG_NAME_ENTRY(WAKE_CONTROL),
    REG_NAME_ENTRY(WAKE_EVENTS),
    REG_NAME_ENTRY(FIFO_CTRL),
    REG_NAME_ENTRY(COUNT_OUT),
    REG_NAME_ENTRY(COUNT_IN),
    REG_NAME_ENTRY(COUNT_NODATA_IN),
    REG_NAME_ENTRY(COUNT_ERRORS),
    /* clang-format on */
};
#undef REG_NAME_ENTRY

/*
 * Forward definitions
 */
static void ot_usbdev_server_report_connected(OtUsbdevState *s, bool connected);

/*
 * State handling
 */
static void ot_usbdev_update_irqs(OtUsbdevState *s)
{
    uint32_t state_masked =
        s->regs[R_USBDEV_INTR_STATE] & s->regs[R_USBDEV_INTR_ENABLE];

    trace_ot_usbdev_irqs(s->ot_id, s->regs[R_USBDEV_INTR_STATE],
                         s->regs[R_USBDEV_INTR_ENABLE], state_masked);

    for (unsigned irq_index = 0u; irq_index < USBDEV_INTR_NUM; irq_index++) {
        bool level = (state_masked & (1U << irq_index)) != 0u;
        ibex_irq_set(&s->irqs[irq_index], level);
    }
}

static void ot_usbdev_update_alerts(OtUsbdevState *s)
{
    uint32_t level = s->regs[R_ALERT_TEST];
    s->regs[R_ALERT_TEST] = 0u;

    /* @todo add other sources of alerts here */

    if (level & R_ALERT_TEST_FATAL_FAULT_MASK) {
        ibex_irq_set(&s->alert, 1);
        ibex_irq_set(&s->alert, 0);
    }
}

/*
 * Determine whether the USBDEV is enabled (ie asserting the pullup).
 *
 * @return true if enabled (USBCTRL.ENABLE is set).
 */
static bool ot_usbdev_is_enabled(const OtUsbdevState *s)
{
    /*
     * Note: this works even if the device is in reset because
     * we clear registers on reset entry.
     */
    return (bool)FIELD_EX32(s->regs[R_USBCTRL], USBCTRL, ENABLE);
}

/*
 * Determine whether VBUS is on.
 *
 * @return true if VBUS is present (USBSTAT.SENSE is set).
 */
static bool ot_usbdev_has_vbus(const OtUsbdevState *s)
{
    /*
     * Note: always returns 0 when device is in reset.
     */
    return FIELD_EX32(s->regs[R_USBSTAT], USBSTAT, SENSE);
}

/*
 * Return the current link state.
 *
 * @return value of USBSTAT.LINK_STATE.
 */
static OtUsbdevLinkState ot_usbdev_get_link_state(const OtUsbdevState *s)
{
    unsigned int v = FIELD_EX32(s->regs[R_USBSTAT], USBSTAT, LINK_STATE);
    /* The SW cannot modify the USBSTAT register but let's be paranoid */
    g_assert(v <= OT_USBDEV_LINK_STATE_COUNT);
    return (OtUsbdevLinkState)v;
}

/*
 * Change the link state in the USBSTAT register and trace change.
 *
 * Note: no events (IRQs, etc) are triggered, this is the caller's
 * responsibility.
 */
static void
ot_usbdev_set_raw_link_state(OtUsbdevState *s, OtUsbdevLinkState state)
{
    OtUsbdevLinkState old_state = ot_usbdev_get_link_state(s);

    if (old_state != state) {
        trace_ot_usbdev_link_state_changed(s->ot_id, LINK_STATE_NAME(state));
    }

    s->regs[R_USBSTAT] =
        FIELD_DP32(s->regs[R_USBSTAT], USBSTAT, LINK_STATE, (uint32_t)state);
}

/*
 * Update the device state after a potential VBUS change.
 *
 * This function will trigger all necessary state and IRQs changes necessary.
 * If the device becomes connected/disconnected as a result, the server will
 * be notified.
 */
static void ot_usbdev_update_vbus(OtUsbdevState *s)
{
    /* Do nothing if the device is in reset */
    if (resettable_is_in_reset(OBJECT(s))) {
        return;
    }

    /*
     * In VBUS override mode, VBUS sense is directly equal to
     * the VBUS gate. Otherwise, it is the AND between the gate
     * and the host VBUS control.
     */
    bool vbus_sense = s->vbus_gate;
    if (!s->vbus_override) {
        vbus_sense = vbus_sense && s->usb_server.vbus_connected;
    }

    bool old_vbus_sense = (bool)FIELD_EX32(s->regs[R_USBSTAT], USBSTAT, SENSE);
    if (old_vbus_sense == vbus_sense) {
        return;
    }

    trace_ot_usbdev_vbus_changed(s->ot_id, vbus_sense);

    s->regs[R_USBSTAT] =
        FIELD_DP32(s->regs[R_USBSTAT], USBSTAT, SENSE, vbus_sense);

    /* VBUS was turned on */
    if (vbus_sense) {
        /* See BFM (bus_connect) */

        /*
         * If we end up in a non-disconnected state here, something is very
         * wrong
         */
        g_assert(ot_usbdev_get_link_state(s) ==
                 OT_USBDEV_LINK_STATE_DISCONNECTED);
        s->regs[R_USBDEV_INTR_STATE] |= USBDEV_INTR_POWERED_MASK;

        if (ot_usbdev_is_enabled(s)) {
            ot_usbdev_set_raw_link_state(s, OT_USBDEV_LINK_STATE_POWERED);
            ot_usbdev_server_report_connected(s, true);
        }
    }
    /* VBUS was turned off */
    else {
        /* See BFM (bus_disconnect) */
        g_assert(ot_usbdev_get_link_state(s) !=
                 OT_USBDEV_LINK_STATE_DISCONNECTED);
        ot_usbdev_set_raw_link_state(s, OT_USBDEV_LINK_STATE_DISCONNECTED);
        s->regs[R_USBDEV_INTR_STATE] |= USBDEV_INTR_DISCONNECTED_MASK;
        s->regs[R_USBCTRL] =
            FIELD_DP32(s->regs[R_USBCTRL], USBCTRL, DEVICE_ADDRESS, 0u);
    }

    ot_usbdev_update_irqs(s);
}

/*
 * Update the VBUS gate.
 *
 * Changes will trigger events (see ot_usbdev_update_vbus).
 *
 * @gate New value of the gate.
 */
static void ot_usbdev_set_vbus_gate(OtUsbdevState *s, bool gate)
{
    s->vbus_gate = gate;

    ot_usbdev_update_vbus(s);
}

/*
 * Simulate a link reset.
 *
 * This function will trigger all necessary state and IRQs changes necessary to
 * perform a link reset.
 *
 * @todo document what happens to transfers when done
 */
static void ot_usbdev_simulate_link_reset(OtUsbdevState *s)
{
    g_assert(!resettable_is_in_reset(OBJECT(s)));

    /* We cannot simulate a reset if the device is disconnected! */
    if (ot_usbdev_get_link_state(s) == OT_USBDEV_LINK_STATE_DISCONNECTED) {
        error_report("%s: %s Link reset while disconnected?!", __func__,
                     s->ot_id);
        return;
    }

    /* See BFM (bus_reset) */
    s->regs[R_USBCTRL] =
        FIELD_DP32(s->regs[R_USBCTRL], USBCTRL, DEVICE_ADDRESS, 0u);
    s->regs[R_USBDEV_INTR_STATE] |= USBDEV_INTR_LINK_RESET_MASK;
    /* @todo cancel all transfers */

    if (ot_usbdev_has_vbus(s) && ot_usbdev_is_enabled(s)) {
        /* @todo BFM has some extra state processing but it seems incorrect */
        ot_usbdev_set_raw_link_state(s, OT_USBDEV_LINK_STATE_ACTIVE_NOSOF);
    }
    ot_usbdev_update_irqs(s);
}

/*
 * Update the value of the USBCTRL register.
 *
 * This function will update the USBCTRL register after a write and
 * trigger the necessary changes if the ENABLE bit is changed. If
 * as a result of this change the device becomes (dis)connected,
 * the server will be notified.
 *
 * @val32 New value
 */
static void ot_usbdev_write_usbctrl(OtUsbdevState *s, uint32_t val32)
{
    bool old_enable = ot_usbdev_is_enabled(s);

    /* @todo Handle resume_link_active eventually, this is a W/O field */
    s->regs[R_USBCTRL] = val32 & USBDEV_USBCTRL_R_MASK;

    bool enable = ot_usbdev_is_enabled(s);
    if (enable == old_enable) {
        return;
    }

    trace_ot_usbdev_enable_changed(s->ot_id, enable);

    /* Device has been enabled */
    if (enable) {
        /* See BFM (set_enable) */
        g_assert(ot_usbdev_get_link_state(s) ==
                 OT_USBDEV_LINK_STATE_DISCONNECTED);
        if (ot_usbdev_has_vbus(s)) {
            ot_usbdev_set_raw_link_state(s, OT_USBDEV_LINK_STATE_POWERED);
            ot_usbdev_server_report_connected(s, true);
        }
        /* @todo Handle FIFO interrupts */
    } else {
        /* See BFM (set_enable) */
        ot_usbdev_set_raw_link_state(s, OT_USBDEV_LINK_STATE_DISCONNECTED);
        s->regs[R_USBDEV_INTR_STATE] |= USBDEV_INTR_DISCONNECTED_MASK;
        s->regs[R_USBCTRL] =
            FIELD_DP32(s->regs[R_USBCTRL], USBCTRL, DEVICE_ADDRESS, 0u);

        if (ot_usbdev_has_vbus(s)) {
            ot_usbdev_server_report_connected(s, false);
        }
        /* @todo Handle FIFO interrupts */
    }

    ot_usbdev_update_irqs(s);
}

/*
 * Register read/write handling
 */

static uint64_t ot_usbdev_read(void *opaque, hwaddr addr, unsigned size)
{
    OtUsbdevState *s = opaque;
    (void)size;
    uint32_t val32;

    hwaddr reg = R32_OFF(addr);
    switch (reg) {
    /* Reads with no side-effects */
    case R_PHY_CONFIG:
    case R_USBSTAT:
    case R_USBDEV_INTR_STATE:
    case R_USBDEV_INTR_ENABLE:
    case R_USBCTRL:
    case R_EP_OUT_ENABLE:
    case R_EP_IN_ENABLE:
    case R_AVOUTBUFFER:
    case R_AVSETUPBUFFER:
    case R_RXFIFO:
    case R_RXENABLE_SETUP:
    case R_RXENABLE_OUT:
    case R_SET_NAK_OUT:
    case R_IN_SENT:
    case R_OUT_STALL:
    case R_IN_STALL:
    case R_CONFIGIN_0:
    case R_CONFIGIN_1:
    case R_CONFIGIN_2:
    case R_CONFIGIN_3:
    case R_CONFIGIN_4:
    case R_CONFIGIN_5:
    case R_CONFIGIN_6:
    case R_CONFIGIN_7:
    case R_CONFIGIN_8:
    case R_CONFIGIN_9:
    case R_CONFIGIN_10:
    case R_CONFIGIN_11:
    case R_OUT_ISO:
    case R_IN_ISO:
    case R_OUT_DATA_TOGGLE:
    case R_IN_DATA_TOGGLE:
    case R_PHY_PINS_SENSE:
    case R_PHY_PINS_DRIVE:
    case R_WAKE_CONTROL:
    case R_WAKE_EVENTS:
    case R_FIFO_CTRL:
    case R_COUNT_OUT:
    case R_COUNT_IN:
    case R_COUNT_NODATA_IN:
    case R_COUNT_ERRORS:
        val32 = s->regs[reg];
        break;
    case R_USBDEV_INTR_TEST:
    case R_ALERT_TEST:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: %s Read to W/O register 0x%02" HWADDR_PRIx " (%s)\n",
                      __func__, s->ot_id, addr, REG_NAME(reg));
        val32 = 0u;
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "%s: %s Bad offset 0x%" HWADDR_PRIx "\n",
                      __func__, s->ot_id, addr);
        val32 = 0u;
        break;
    }

    uint32_t pc = ibex_get_current_pc();
    trace_ot_usbdev_io_read_out(s->ot_id, (uint32_t)addr, REG_NAME(reg), val32,
                                pc);

    return (uint64_t)val32;
}

static void ot_usbdev_write(void *opaque, hwaddr addr, uint64_t val64,
                            unsigned size)
{
    OtUsbdevState *s = opaque;
    (void)size;
    uint32_t val32 = (uint32_t)val64;

    hwaddr reg = R32_OFF(addr);

    uint32_t pc = ibex_get_current_pc();
    trace_ot_usbdev_io_write(s->ot_id, (uint32_t)addr, REG_NAME(reg), val32,
                             pc);

    switch (reg) {
    case R_USBDEV_INTR_STATE:
        if (val32 & ~USBDEV_INTR_RW1C_MASK) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "%s: %s: write to R/O register 0x%02" HWADDR_PRIx
                          " (%s) field 0x%08x\n",
                          __func__, s->ot_id, addr, REG_NAME(reg),
                          val32 & ~USBDEV_INTR_RW1C_MASK);
        }
        val32 &= USBDEV_INTR_RW1C_MASK;
        s->regs[reg] &= ~val32;
        ot_usbdev_update_irqs(s);
        break;
    case R_USBDEV_INTR_ENABLE:
        val32 &= USBDEV_INTR_MASK;
        s->regs[reg] = val32;
        ot_usbdev_update_irqs(s);
        break;
    case R_USBDEV_INTR_TEST:
        val32 &= USBDEV_INTR_MASK;
        s->regs[R_USBDEV_INTR_STATE] |= val32;
        ot_usbdev_update_irqs(s);
        break;
    case R_ALERT_TEST:
        val32 &= R_ALERT_TEST_FATAL_FAULT_MASK;
        /* Use the register to record alerts sets */
        s->regs[R_ALERT_TEST] = val32;
        ot_usbdev_update_alerts(s);
        break;
    case R_USBSTAT:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: %s: write to R/O register 0x%02" HWADDR_PRIx
                      " (%s)\n",
                      __func__, s->ot_id, addr, REG_NAME(reg));
        break;
    /* Writes without side-effects */
    case R_PHY_CONFIG:
        /* @todo mask against actual fields? */
        s->regs[R_PHY_CONFIG] = val32;
        break;
    case R_USBCTRL:
        ot_usbdev_write_usbctrl(s, val32);
        break;
    case R_EP_OUT_ENABLE:
    case R_EP_IN_ENABLE:
    case R_AVOUTBUFFER:
    case R_AVSETUPBUFFER:
    case R_RXFIFO:
    case R_RXENABLE_SETUP:
    case R_RXENABLE_OUT:
    case R_SET_NAK_OUT:
    case R_IN_SENT:
    case R_OUT_STALL:
    case R_IN_STALL:
    case R_CONFIGIN_0:
    case R_CONFIGIN_1:
    case R_CONFIGIN_2:
    case R_CONFIGIN_3:
    case R_CONFIGIN_4:
    case R_CONFIGIN_5:
    case R_CONFIGIN_6:
    case R_CONFIGIN_7:
    case R_CONFIGIN_8:
    case R_CONFIGIN_9:
    case R_CONFIGIN_10:
    case R_CONFIGIN_11:
    case R_OUT_ISO:
    case R_IN_ISO:
    case R_OUT_DATA_TOGGLE:
    case R_IN_DATA_TOGGLE:
    case R_PHY_PINS_SENSE:
    case R_PHY_PINS_DRIVE:
    case R_WAKE_CONTROL:
    case R_WAKE_EVENTS:
    case R_FIFO_CTRL:
    case R_COUNT_OUT:
    case R_COUNT_IN:
    case R_COUNT_NODATA_IN:
    case R_COUNT_ERRORS:
        s->regs[reg] = val32;
        qemu_log_mask(LOG_UNIMP, "%s: %s: %s is not supported\n", __func__,
                      s->ot_id, REG_NAME(reg));
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "%s: %s Bad offset 0x%" HWADDR_PRIx "\n",
                      __func__, s->ot_id, addr);
        break;
    }
}

static uint64_t ot_usbdev_buffer_read(void *opaque, hwaddr addr, unsigned size)
{
    OtUsbdevState *s = opaque;
    (void)size;

    hwaddr word = R32_OFF(addr);
    uint32_t val32 = s->buffer[word];

    uint32_t pc = ibex_get_current_pc();
    trace_ot_usbdev_io_buffer_read_out(s->ot_id, (uint32_t)addr, val32, pc);

    return (uint64_t)val32;
}

static void ot_usbdev_buffer_write(void *opaque, hwaddr addr, uint64_t val64,
                                   unsigned size)
{
    OtUsbdevState *s = opaque;
    (void)size;
    uint32_t val32 = val64;

    hwaddr word = R32_OFF(addr);
    s->buffer[word] = val32;

    uint32_t pc = ibex_get_current_pc();
    trace_ot_usbdev_io_buffer_write(s->ot_id, (uint32_t)addr, val32, pc);
}

/*
 * USB server
 */
static void ot_usbdev_server_reset_recv_state(OtUsbdevState *s)
{
    OtUsbdevServer *server = &s->usb_server;

    /* cleanup previous state */
    g_free(server->recv_data);
    server->recv_data = NULL;

    server->recv_state = OT_USBDEV_SERVER_RECV_WAIT_HEADER;
    server->recv_rem = sizeof(server->recv_pkt);
    server->recv_buf = (uint8_t *)&server->recv_pkt;
}

/*
 * Open a session with the server.
 *
 * This function will reset the server state to start a new session.
 */
static void ot_usbdev_server_open(OtUsbdevState *s)
{
    OtUsbdevServer *server = &s->usb_server;
    server->client_connected = true;
    server->vbus_connected = false;
    server->hello_done = false;
    ot_usbdev_server_reset_recv_state(s);

    ot_usbdev_update_vbus(s);
}

/*
 * Close a session with the server.
 *
 * In particular, if VBUS is still on, it will be turned off by this call,
 * which can trigger events on the device side.
 */
static void ot_usbdev_server_close(OtUsbdevState *s)
{
    OtUsbdevServer *server = &s->usb_server;
    server->client_connected = false;
    server->vbus_connected = false;

    ot_usbdev_update_vbus(s);
}

/*
 * Send a message to the client.
 *
 * @todo clarify blocking/non-blocking
 */
static void ot_usbdev_server_write_packet(OtUsbdevState *s,
                                          OtUsbdevServerCmd cmd, uint32_t id,
                                          const void *data, size_t size)
{
    /*
     * @todo Update this to handle partial writes, by adding them to a queue and
     * using a watch callback
     */
    const OtUsbdevServerPktHdr hdr = {
        .cmd = cmd,
        .size = size,
        .id = id,
    };
    int res =
        qemu_chr_fe_write(&s->usb_chr, (const uint8_t *)&hdr, sizeof(hdr));
    if (res < sizeof(hdr)) {
        qemu_log_mask(LOG_UNIMP, "%s: %s server: unhandled partial write\n",
                      __func__, s->ot_id);
        return;
    }
    if (size > 0u) {
        res = qemu_chr_fe_write(&s->usb_chr, (const uint8_t *)data, (int)size);
        if (res < size) {
            qemu_log_mask(LOG_UNIMP, "%s: %s server: unhandled partial write\n",
                          __func__, s->ot_id);
            return;
        }
    }
}

/*
 * Report a (dis)connection event to the client.
 *
 * Send a message to the client to notify the connection status change.
 * Note that this function does not keep track of the current status and will
 * send a message if the new status is the same as the old one.
 *
 * @connected New connection status
 */
void ot_usbdev_server_report_connected(OtUsbdevState *s, bool connected)
{
    trace_ot_usbdev_server_report_connected(s->ot_id, connected);

    /* Nothing to do if no client is connected */
    if (!s->usb_server.client_connected) {
        return;
    }

    /* @todo clarify ID to use */
    ot_usbdev_server_write_packet(s,
                                  connected ? OT_USBDEV_SERVER_CMD_CONNECT :
                                              OT_USBDEV_SERVER_CMD_DISCONNECT,
                                  0u, NULL, 0u);
}

/*
 * Process a HELLO packet from the client and send one back.
 *
 * After this function, the server will be ready to receive messages from
 * the client, unless the packet was invalid in which case the server will
 * keep expecting a valid HELLO packet.
 */
static void ot_usbdev_server_process_hello(OtUsbdevState *s)
{
    OtUsbdevServer *server = &s->usb_server;

    if (server->hello_done) {
        error_report("%s: %s server: unexpected HELLO\n", __func__, s->ot_id);
        /* Not a fatal error */
    }
    if (server->recv_pkt.size != sizeof(OtUsbdevServerHelloPkt)) {
        error_report("%s: %s server: HELLO packet with unexpected payload "
                     "size %u, ignoring packet\n",
                     __func__, s->ot_id, server->recv_pkt.size);
        return;
    }
    /*
     * @todo maybe recover packet ID and drop any packet with ID smaller than
     * the last hello?
     */
    OtUsbdevServerHelloPkt hello;
    memcpy(&hello, server->recv_data, sizeof(OtUsbdevServerHelloPkt));
    if (memcmp(hello.magic, OT_USBDEV_SERVER_HELLO_MAGIC,
               sizeof(hello.magic)) != 0) {
        error_report("%s: %s server: HELLO packet with unexpected magic value "
                     "%.4s, ignoring packet\n",
                     __func__, s->ot_id, hello.magic);
        return;
    }
    if (hello.major_version != OT_USBDEV_SERVER_MAJOR_VER ||
        hello.minor_version != OT_USBDEV_SERVER_MINOR_VER) {
        error_report("%s: %s server: HELLO packet with unexpected version "
                     "version %d.%d, ignoring packet\n",
                     __func__, s->ot_id, hello.major_version,
                     hello.minor_version);
        return;
    }
    server->hello_done = true;

    trace_ot_usbdev_server_hello(s->ot_id, hello.major_version,
                                 hello.minor_version);

    /* Answer back */
    OtUsbdevServerHelloPkt resp_hello;
    memcpy(&resp_hello.magic, OT_USBDEV_SERVER_HELLO_MAGIC,
           sizeof(resp_hello.magic));
    resp_hello.major_version = OT_USBDEV_SERVER_MAJOR_VER;
    resp_hello.minor_version = OT_USBDEV_SERVER_MINOR_VER;
    ot_usbdev_server_write_packet(s, OT_USBDEV_SERVER_CMD_HELLO,
                                  server->recv_pkt.id,
                                  (const void *)&resp_hello,
                                  sizeof(resp_hello));
}

static void ot_usbdev_server_process_reset(OtUsbdevState *s)
{
    OtUsbdevServer *server = &s->usb_server;

    if (server->recv_pkt.size != 0u) {
        error_report("%s: %s server: RESET packet with unexpected payload, "
                     "ignoring packet\n",
                     __func__, s->ot_id);
        return;
    }
    /* Ignore if device is not enabled */
    if (resettable_is_in_reset(OBJECT(s))) {
        error_report(
            "%s: %s server: RESET when device is in reset, ignoring packet\n",
            __func__, s->ot_id);
        return;
    }

    ot_usbdev_simulate_link_reset(s);
}

static void ot_usbdev_server_process_vbus_changed(OtUsbdevState *s, bool vbus)
{
    OtUsbdevServer *server = &s->usb_server;

    if (server->recv_pkt.size != 0u) {
        error_report("%s: %s server: VBUS_ON/OFF packet with unexpected "
                     "payload, ignoring packet\n",
                     __func__, s->ot_id);
        return;
    }

    server->vbus_connected = vbus;
    ot_usbdev_update_vbus(s);
}

static void ot_usbdev_server_process_packet(OtUsbdevState *s)
{
    OtUsbdevServer *server = &s->usb_server;

    /*
     * Important note: the ->recv_data pointer is freed in
     * ot_usbdev_server_reset_recv_state() if left non-NULL. The code below must
     * either make a copy of the data or take ownership of the pointer and set
     * ->recv_data to NULL.
     */

    /* If HELLO hasn't been received yet, ignore everything else */
    if (server->recv_pkt.cmd != OT_USBDEV_SERVER_CMD_HELLO &&
        !server->hello_done) {
        error_report("%s: %s server: unexpected command %u before HELLO\n",
                     __func__, s->ot_id, server->recv_pkt.cmd);
        /* Do not process packet */
        return;
    }

    switch (server->recv_pkt.cmd) {
    case OT_USBDEV_SERVER_CMD_HELLO:
        ot_usbdev_server_process_hello(s);
        break;
    case OT_USBDEV_SERVER_CMD_RESET:
        ot_usbdev_server_process_reset(s);
        break;
    case OT_USBDEV_SERVER_CMD_VBUS_ON:
        ot_usbdev_server_process_vbus_changed(s, true);
        break;
    case OT_USBDEV_SERVER_CMD_VBUS_OFF:
        ot_usbdev_server_process_vbus_changed(s, false);
        break;
    default:
        error_report("%s: %s server: unknown packet type %u, ignoring packet\n",
                     __func__, s->ot_id, server->recv_pkt.cmd);
        break;
    }

    ot_usbdev_server_reset_recv_state(s);
}

static void ot_usbdev_server_advance_recv_state(OtUsbdevState *s)
{
    OtUsbdevServer *server = &s->usb_server;

    if (server->recv_state == OT_USBDEV_SERVER_RECV_WAIT_HEADER) {
        /* We received a header, now receive data if necessary */
        if (server->recv_pkt.size > 0u) {
            /* @todo have some bound on allocation size here? */
            server->recv_data = g_malloc(server->recv_pkt.size);
            server->recv_rem = server->recv_pkt.size;
            server->recv_buf = (uint8_t *)server->recv_data;
            server->recv_state = OT_USBDEV_SERVER_RECV_WAIT_DATA;
        } else {
            /* Process packet */
            ot_usbdev_server_process_packet(s);
        }
    } else if (server->recv_state == OT_USBDEV_SERVER_RECV_WAIT_DATA) {
        /* Process packet */
        ot_usbdev_server_process_packet(s);
    } else {
        g_assert_not_reached();
    }
}

static int ot_usbdev_chr_usb_can_receive(void *opaque)
{
    OtUsbdevState *s = opaque;

    /* Return remaining size in the buffer. */
    return (int)s->usb_server.recv_rem;
}

static void ot_usbdev_chr_usb_receive(void *opaque, const uint8_t *buf,
                                      int size)
{
    OtUsbdevState *s = opaque;
    OtUsbdevServer *server = &s->usb_server;

    if (size > server->recv_rem) {
        error_report("%s: %s: Received too much data on the usb chardev",
                     __func__, s->ot_id);
        return;
    }
    /* Copy data at the end of the buffer. */
    memcpy(server->recv_buf, buf, (size_t)size);
    server->recv_buf += size;
    server->recv_rem -= size;

    /* Advance state if done */
    if (server->recv_rem == 0u) {
        ot_usbdev_server_advance_recv_state(s);
    }
}

static void ot_usbdev_chr_usb_event_handler(void *opaque, QEMUChrEvent event)
{
    OtUsbdevState *s = opaque;

    trace_ot_usbdev_chr_usb_event_handler(s->ot_id, event);

    if (event == CHR_EVENT_OPENED) {
        ot_usbdev_server_open(s);
    }

    if (event == CHR_EVENT_CLOSED) {
        ot_usbdev_server_close(s);
    }
}

/*
 * Communication device handling
 */

static int ot_usbdev_chr_cmd_can_receive(void *opaque)
{
    OtUsbdevState *s = opaque;

    /* Return remaining size in the buffer. */
    return (int)sizeof(s->cmd_buf) - (int)s->cmd_buf_pos;
}

/*
 * Process a nul-terminated command. A size (which does not count NUL) is
 * provided if necessary. The following commands are supported:
 * - "vbus_on": set the VBUS sensing signal to 1.
 * - "vbus_off": set the VBUS sensing signal to 0.
 */
static void ot_usbdev_chr_process_cmd(OtUsbdevState *s, char *cmd,
                                      size_t cmd_size)
{
    trace_ot_usbdev_chr_process_cmd(s->ot_id, cmd);

    if (strncmp(cmd, "vbus_on", cmd_size) == 0) {
        ot_usbdev_set_vbus_gate(s, true);
    } else if (strncmp(cmd, "vbus_off", cmd_size) == 0) {
        ot_usbdev_set_vbus_gate(s, false);
    } else {
        qemu_log_mask(LOG_UNIMP, "%s: %s: unsupported command %s\n", __func__,
                      s->ot_id, cmd);
    }
}

static void ot_usbdev_chr_cmd_receive(void *opaque, const uint8_t *buf,
                                      int size)
{
    OtUsbdevState *s = opaque;

    if (s->cmd_buf_pos + (unsigned)size > sizeof(s->cmd_buf)) {
        error_report("%s: %s: Received too much data on the cmd chardev",
                     __func__, s->ot_id);
        return;
    }
    /* Copy data at the end of the buffer. */
    memcpy(&s->cmd_buf[s->cmd_buf_pos], buf, (size_t)size);
    s->cmd_buf_pos += (unsigned)size;
    /* Process any line. */
    while (true) {
        /* Search end of line, stop if none is found. */
        char *eol = memchr(s->cmd_buf, (int)'\n', s->cmd_buf_pos);
        if (!eol) {
            break;
        }
        *eol = 0;
        /*
         * Process command and then remove it from the buffer
         * by shifting everything left.
         */
        size_t cmd_size = eol - s->cmd_buf;
        ot_usbdev_chr_process_cmd(s, s->cmd_buf, cmd_size);
        memmove(s->cmd_buf, eol + 1u, s->cmd_buf_pos - cmd_size - 1u);
        s->cmd_buf_pos -= cmd_size - 1u;
    }
}

/*
 * QEMU Initialization
 */

static const MemoryRegionOps ot_usbdev_ops = {
    .read = &ot_usbdev_read,
    .write = &ot_usbdev_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl.min_access_size = sizeof(uint32_t),
    .impl.max_access_size = sizeof(uint32_t),
};

static const MemoryRegionOps ot_usbdev_buffer_ops = {
    .read = &ot_usbdev_buffer_read,
    .write = &ot_usbdev_buffer_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    /* @todo The RTL probably supports sub-word reads, implement this */
    .impl.min_access_size = sizeof(uint32_t),
    .impl.max_access_size = sizeof(uint32_t),
};

static Property ot_usbdev_properties[] = {
    DEFINE_PROP_STRING("ot_id", OtUsbdevState, ot_id),
    DEFINE_PROP_STRING("clock-name", OtUsbdevState, usbclk_name),
    DEFINE_PROP_STRING("clock-name-aon", OtUsbdevState, aonclk_name),
    DEFINE_PROP_LINK("clock-src", OtUsbdevState, clock_src, TYPE_DEVICE,
                     DeviceState *),
    /*
     * Communication device used to control the USBDEV block. Every command
     * must be terminated by a newline. See ot_usbdev_chr_process_cmd for
     * the list of supported devices.
     */
    DEFINE_PROP_CHR("chardev-cmd", OtUsbdevState, cmd_chr),
    /*
     * Communication device used to emulate a USB host.
     */
    DEFINE_PROP_CHR("chardev-usb", OtUsbdevState, usb_chr),
    /* VBUS control mode. */
    DEFINE_PROP_BOOL("vbus-override", OtUsbdevState, vbus_override, false),
    DEFINE_PROP_END_OF_LIST(),
};

static void ot_usbdev_realize(DeviceState *dev, Error **errp)
{
    OtUsbdevState *s = OT_USBDEV(dev);
    (void)errp;

    /* @todo: clarify if we need to track events/backend changes. */
    qemu_chr_fe_set_handlers(&s->cmd_chr, &ot_usbdev_chr_cmd_can_receive,
                             &ot_usbdev_chr_cmd_receive, NULL, NULL, s, NULL,
                             true);

    qemu_chr_fe_set_handlers(&s->usb_chr, &ot_usbdev_chr_usb_can_receive,
                             &ot_usbdev_chr_usb_receive,
                             &ot_usbdev_chr_usb_event_handler, NULL, s, NULL,
                             true);

    g_assert(s->ot_id);
    g_assert(s->usbclk_name);
    g_assert(s->aonclk_name);

    /* If not in VBUS override mode, the VBUS gate starts on by default. */
    if (!s->vbus_override) {
        s->vbus_gate = true;
    }
}

/*
 * QEMU reset handling
 */

static void ot_usbdev_reset_enter(Object *obj, ResetType type)
{
    OtUsbdevClass *c = OT_USBDEV_GET_CLASS(obj);
    OtUsbdevState *s = OT_USBDEV(obj);

    trace_ot_usbdev_reset(s->ot_id, "enter");

    if (c->parent_phases.enter) {
        c->parent_phases.enter(obj, type);
    }

    /* @todo cancel everything here. */

    /* See BFM (dut_reset) */
    memset(s->regs, 0, sizeof(s->regs));
    /*
     * @todo The BFM says that 'Disconnected' is held at 1 during IP
     * reset, need to investigate this detail.
     */
    ot_usbdev_update_irqs(s);
}

static void ot_usbdev_reset_exit(Object *obj, ResetType type)
{
    OtUsbdevClass *c = OT_USBDEV_GET_CLASS(obj);
    OtUsbdevState *s = OT_USBDEV(obj);

    trace_ot_usbdev_reset(s->ot_id, "exit");

    if (c->parent_phases.exit) {
        c->parent_phases.exit(obj, type);
    }

    ot_usbdev_update_vbus(s);
}

static void ot_usbdev_init(Object *obj)
{
    OtUsbdevState *s = OT_USBDEV(obj);

    for (unsigned idx = 0u; idx < ARRAY_SIZE(s->irqs); idx++) {
        ibex_sysbus_init_irq(obj, &s->irqs[idx]);
    }
    ibex_qdev_init_irq(obj, &s->alert, OT_DEVICE_ALERT);

    memory_region_init(&s->mmio.main, obj, TYPE_OT_USBDEV ".mmio",
                       USBDEV_DEVICE_SIZE);
    sysbus_init_mmio(SYS_BUS_DEVICE(obj), &s->mmio.main);
    memory_region_init_io(&s->mmio.regs, obj, &ot_usbdev_ops, s,
                          TYPE_OT_USBDEV ".reg", USBDEV_REGS_SIZE);
    memory_region_add_subregion(&s->mmio.main, USBDEV_REGS_OFFSET,
                                &s->mmio.regs);
    memory_region_init_io(&s->mmio.buffer, obj, &ot_usbdev_buffer_ops, s,
                          TYPE_OT_USBDEV ".buffer", USBDEV_BUFFER_SIZE);
    memory_region_add_subregion(&s->mmio.main, USBDEV_BUFFER_OFFSET,
                                &s->mmio.buffer);
}

static void ot_usbdev_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    (void)data;

    dc->realize = &ot_usbdev_realize;
    device_class_set_props(dc, ot_usbdev_properties);
    /* @todo: check what does DEVICE_CATEGORY_USB entail? */
    set_bit(DEVICE_CATEGORY_USB, dc->categories);

    ResettableClass *rc = RESETTABLE_CLASS(klass);
    OtUsbdevClass *uc = OT_USBDEV_CLASS(klass);
    resettable_class_set_parent_phases(rc, &ot_usbdev_reset_enter, NULL,
                                       &ot_usbdev_reset_exit,
                                       &uc->parent_phases);
}

static const TypeInfo ot_usbdev_info = {
    .name = TYPE_OT_USBDEV,
    .parent = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(OtUsbdevState),
    .instance_init = &ot_usbdev_init,
    .class_size = sizeof(OtUsbdevClass),
    .class_init = &ot_usbdev_class_init,
};

static void ot_usbdev_register_types(void)
{
    type_register_static(&ot_usbdev_info);
}

type_init(ot_usbdev_register_types);
