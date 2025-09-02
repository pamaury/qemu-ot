# OpenTitan USBDEV

**Warning:** the USBDEV driver is still in development and not expected to work at the moment!

## `usb` Chardev

The USBDEV driver exposes a chardev with ID `usbdev` which can used to control some aspects of the
emulation.
Once connected, the driver accepts textual commands.
Each command must end with a newline.
The following commands are recognized:
- `vbus_on`: turn on VBUS, see [#VBUS-handling](VBUS handling) for more details.
- `vbus_off`: turn off VBUS, see [#VBUS-handling](VBUS handling) for more details.

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
  gate is enabled **and** a USB host is connected to the driver.
  By default, the VBUS gate is disabled.
