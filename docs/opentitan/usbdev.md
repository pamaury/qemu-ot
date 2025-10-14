# OpenTitan USBDEV

**Warning:** the USBDEV driver is still in development and not expected to work at the moment!

## `usbdev-cmd` Chardev

The USBDEV driver exposes a chardev with ID `usbdev-cmd` which can used to control some aspects of the
emulation.
Once connected, the driver accepts textual commands.
Each command must end with a newline.
The following commands are recognized:
- `vbus_on`: turn on VBUS, see [VBUS handling](#VBUS-handling) for more details.
- `vbus_off`: turn off VBUS, see [VBUS handling](#VBUS-handling) for more details.

## `usbdev-host` Chardev

The USBDEV driver exposes a chardev with ID `usbdev-host` which can used to simulate the presence of
a USB host. The implementation is such that the USBDEV behaves as a server, waiting for a connection
from a virtual host. Once connected, the host and device exchange  binary commands following the protocol
described in the [host simulation](#host-simulation) section.

## VBUS handling

On a real machine, the VBUS sense pin is usually connected to the VBUS connector so
that the chip can detect when a cable is plugged in. For the purpose of emulation, a different
approach needs to be taken. The driver supports two modes of operation which are controlled
by the `vbus-override` property which can be set on the command-line by
`-global ot-usbdev.vbus-override=<mode>`. The following modes are supported:

- `vbus-override=on`: in this mode, the VBUS sense pin is entirely managed over the `usbdev`
  chardev.
  By default, the sense pin will be set to level low. The `vbus_on` and `vbus_off` commands
  can be used to change the value of the sense pin. Note that in this mode, the VBUS sense signal
  will be completely independent of the presence of a USB host.
- `vbus-override=off`: in this mode, the `vbus_on` and `vbus_off` commands control a virtual "VBUS
  enable" gate. The VBUS sense pin will be reported as level high if and only if the VBUS enable
  gate is enabled **and** a USB host has enabled VBUS (see [host simulation](#host-simulation))
  By default, the VBUS gate is enabled.

## Host simulation

The QEMU USBDEV driver only simulates a USB device controller (UDC) which requires the presence
of a USB host. A (virtual) host exchanges messages with the UDC over the [`udev-host` chardev](#usbdev-host-chardev).
This binary protocol is somewhat similar to the [USB/IP][usbip]
protocol but lower level. This protocol is also different from the [USB network redirection (a.k.a usbredir)][usbredir]
protocol supported by QEMU.

[usbip]: (https://docs.kernel.org/usb/usbip_protocol.html)
[usbredir]: (https://gitlab.freedesktop.org/spice/usbredir/-/blob/main/docs/usb-redirection-protocol.md)

### Rationale for a different protocol

Both the USB/IP and usbredir protocols are too high-level for the purpose of emulating and testing a low-level
UDC driver. For example, both protocols require that the device be fully enumerated and configured before the
host is even made aware of its presence. In contrast, we want to be able to fully emulate the enumeration sequence.
Another big difference is bus management: USB/IP does not support bus resets and usbredir does not support resume/suspend,
and neither models VBUS. This is a side-effect of the intended use case of these protocols: to connect a real USB device
to a virtual USB host. However, this new protocol should be low-level enough that it is possible to implement a
bridge from either usbredir or USB/IP to this protocol (while losing some features).

### High-level overview

This protocol does not specify which of the device or the host should be the client/guest.
On connection, the client must send a [`Hello` command](#hello-command), to which the server
must respond with another `Hello` command. After that, messages are exchanged asynchronously.

#### Bus states

The protocol reflects the low-level details of the USB bus and provides independent
handling of VBUS (controlled by the host) and connection (controlled by the device).
The host can turn VBUS on and off at any point. When VBUS is on, the device can freely
connect or disconnect by asynchronously sending a message to the host. As on a real bus,
turning off VBUS disconnects the device. VBUS is assumed to be initially off.

It is an error for the device to send a message when VBUS is not on and the host must ignore such
messages. However due to the asynchronous nature of the protocol, it is possible for the host to
receive a message event *after* sending a `VBUS Off` message which was sent *before* reception of
this message by the device. The ID of the message makes it clear when this is the case so that
the host can safely ignore those messages.

When VBUS is turned on, the host assumes that the device is *not* connected. The device must
send a `Connect` message to notify the host.

While VBUS is turned on, the host can reset, suspend or resume the device. As on a real bus,
the device will become unconfigured after a bus reset and an enumeration sequence must be performed.

**TODO** Clarify suspend/resume

### Packet format

The protocol is based on packets which are exchanged asynchronously by the device and host. Each packet starts
with a header followed by a payload. All fields are in little-endian.

| **Field** | **Offset** | **Size** | **Value** |
| --------- | ---------- | -------- | --------- |
| Command   |      0     |     4    | Command number (see below) |
| Size      |      4     |     4    | Size of the payload (header excluded)
| Packet ID |      8     |     4    | Unique ID used to match responses |

The host must increase the ID of its message by one each time it sends a message.
The ID used by the device is defined in the respective sections of their commands.

The following commands are defined.

| **Command** | **Value** | **Direction** | **Description** | **Reference** |
| ----------- | --------- | ------------- | --------------- | ------------- |
| Invalid     |     0     | N/A           |  To avoid 0 meaning something | |
| Hello       |     1     | Both          | First packet sent when connecting | [`Hello` command](#hello-command) |
| VBUS On     |     2     | Host to device | Turn VBUS on | [Bus commands](#bus-commands) |
| VBUS Off    |     3     | Host to device | Turn VBUS off | [Bus commands](#bus-commands) |
| Connect     |     4     | Device to host | Report device connection | [Bus commands](#bus-commands) |
| Disconnect  |     5     | Device to host | Report device disconnection | [Bus commands](#bus-commands) |
| Reset       |     6     | Host to device | Reset the device | [Bus commands](#bus-commands) |
| Resume      |     7     | Host to device | Resume the device | [Bus commands](#bus-commands) |
| Suspend     |     8     | Host to device | Suspend the device | [Bus commands](#bus-commands) |

**TODO** Add transfer commands

#### Hello command

The ID of this command must be 0.
The payload of this command is defined as follows.

| **Field** | **Offset** | **Size** | **Value** |
| --------- | ---------- | -------- | --------- |
| Magic value |      0   |     4    | String `UDCX` |
| Major version |   4    |     2    |      1    |
| Minor version |   6    |     2    |     0     |

#### Bus commands

These commands (VBUS On/Off, (Dis)connection, Reset, Suspend/Resume) do not have any payload.
See the [bus states](#bus-states) section for more detail.

For the Connect/Disconnect commands, which are sent by the device, the ID should be the ID of the *last command*
processed by the device.
