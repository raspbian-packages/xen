/*
 * QEMU SMBus EEPROM device
 * 
 * Copyright (c) 2007 Arastra, Inc.
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

#include "vl.h"

//#define DEBUG

typedef struct SMBusEEPROMDevice {
    SMBusDevice dev;
    uint8_t *data;
    uint8_t offset;
} SMBusEEPROMDevice;

static void eeprom_quick_cmd(SMBusDevice *dev, uint8_t read)
{
#ifdef DEBUG
    printf("eeprom_quick_cmd: addr=0x%02x read=%d\n", dev->addr, read);
#endif
}

static void eeprom_send_byte(SMBusDevice *dev, uint8_t val)
{
    SMBusEEPROMDevice *eeprom = (SMBusEEPROMDevice *) dev;
#ifdef DEBUG
    printf("eeprom_send_byte: addr=0x%02x val=0x%02x\n", dev->addr, val);
#endif
    eeprom->offset = val;
}

static uint8_t eeprom_receive_byte(SMBusDevice *dev)
{
    SMBusEEPROMDevice *eeprom = (SMBusEEPROMDevice *) dev;
    uint8_t val = eeprom->data[eeprom->offset++];
#ifdef DEBUG
    printf("eeprom_receive_byte: addr=0x%02x val=0x%02x\n", dev->addr, val);
#endif
    return val;
}

static void eeprom_write_byte(SMBusDevice *dev, uint8_t cmd, uint8_t val)
{
    SMBusEEPROMDevice *eeprom = (SMBusEEPROMDevice *) dev;
#ifdef DEBUG
    printf("eeprom_write_byte: addr=0x%02x cmd=0x%02x val=0x%02x\n", dev->addr,
           cmd, val);
#endif
    eeprom->data[cmd] = val;
}

static uint8_t eeprom_read_byte(SMBusDevice *dev, uint8_t cmd)
{
    SMBusEEPROMDevice *eeprom = (SMBusEEPROMDevice *) dev;
    uint8_t val = eeprom->data[cmd];
#ifdef DEBUG
    printf("eeprom_read_byte: addr=0x%02x cmd=0x%02x val=0x%02x\n", dev->addr,
           cmd, val);
#endif
    return val;
}

SMBusDevice *smbus_eeprom_device_init(uint8_t addr, uint8_t *buf)
{
    SMBusEEPROMDevice *eeprom = qemu_mallocz(sizeof(SMBusEEPROMDevice));
    eeprom->dev.addr = addr;
    eeprom->dev.quick_cmd = eeprom_quick_cmd;
    eeprom->dev.send_byte = eeprom_send_byte;
    eeprom->dev.receive_byte = eeprom_receive_byte;
    eeprom->dev.write_byte = eeprom_write_byte;
    eeprom->dev.read_byte = eeprom_read_byte;
    eeprom->data = buf;
    eeprom->offset = 0;
    return (SMBusDevice *) eeprom;
}
