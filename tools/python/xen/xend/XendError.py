#============================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
# Copyright (c) 2006, 2007 XenSource Inc.
#============================================================================

from xmlrpclib import Fault

import XendClient

class XendInvalidDomain(Fault):
    def __init__(self, value):
        Fault.__init__(self, XendClient.ERROR_INVALID_DOMAIN, value)

class XendError(Fault):
    
    def __init__(self, value):
        Fault.__init__(self, XendClient.ERROR_GENERIC, value)
        self.value = value

    def __str__(self):
        return self.value

class VMBadState(XendError):
    def __init__(self, value, expected, actual):
        XendError.__init__(self, value)
        self.expected = expected
        self.actual = actual

class NetworkAlreadyConnected(XendError):
    def __init__(self, pif_uuid):
        XendError.__init__(self, 'Network already connected')
        self.pif_uuid = pif_uuid

class PIFIsPhysical(XendError):
    def __init__(self):
        XendError.__init__(self, 'PIF is physical')

class VmError(XendError):
    """Vm construction error."""
    pass

class HVMRequired(VmError):
    def __init__(self):
        XendError.__init__(self,
                           'HVM guest support is unavailable: is VT/AMD-V '
                           'supported by your CPU and enabled in your BIOS?')

class XendAPIError(XendError):
    """Extend this class for all error thrown by
    autoplugged classes"""
    def __init__(self):
        XendError.__init__(self, 'XendAPI Error: You should never see this'
                           ' message; this class need to be overidden')

    def get_api_error(self):
        return ['INTERNAL_ERROR', 'You should never see this message; '
                'this method needs to be overidden']

class CreateUnspecifiedAttributeError(XendAPIError):
    def __init__(self, attr_name, class_name):
        XendAPIError.__init__(self)
        self.attr_name = attr_name
        self.class_name = class_name

    def get_api_error(self):
        return ['CREATE_UNSPECIFIED_ATTRIBUTE', self.attr_name,
                self.class_name]

    def __str__(self):
        return "CREATE_UNSPECIFIED_ATTRIBUTE: %s, %s" % (self.attr_name,
                 self.class_name)

class UnmanagedNetworkError(XendAPIError):
    def __init__(self, attr_name):
        XendAPIError.__init__(self)
        self.attr_name = attr_name

    def get_api_error(self):
        return ['UNMANAGED_NETWORK_ERROR', self.attr_name]

    def __str__(self):
        return "UNMANAGED_NETWORK_ERROR: %s" % self.attr_name

class UniqueNameError(XendAPIError):
    def __init__(self, name, class_name):
        XendAPIError.__init__(self)
        self.name = name
        self.class_name = class_name
        
    def get_api_error(self):
        return ['UNIQUE_NAME_ERROR', self.name, self.class_name]        

    def __str__(self):
        return 'UNIQUE_NAME_ERROR: %s, %s' % (self.name, self.class_name)

class InvalidDeviceError(XendAPIError):
    def __init__(self, dev):
        XendAPIError.__init__(self)
        self.dev = dev
        
    def get_api_error(self):
        return ['INVALID_DEVICE_ERROR', self.dev]        

    def __str__(self):
        return 'INVALID_DEVICE_ERROR: %s' % self.dev
    
class DeviceExistsError(XendAPIError):
    def __init__(self, dev):
        XendAPIError.__init__(self)
        self.dev = dev
        
    def get_api_error(self):
        return ['DEVICE_EXISTS_ERROR', self.dev]        

    def __str__(self):
        return 'DEVICE_EXISTS_ERROR: %s' % self.dev

class InvalidHandleError(XendAPIError):
    def __init__(self, klass, handle):
        XendAPIError.__init__(self)
        self.klass = klass
        self.handle = handle
        
    def get_api_error(self):
        return ['HANDLE_INVALID', self.klass, self.handle]        

    def __str__(self):
        return 'HANDLE_INVALID: %s %s' % (self.klass, self.handle)

class ImplementationError(XendAPIError):
    def __init__(self, klass, func):
        XendAPIError.__init__(self)
        self.klass = klass
        self.func = func

    def get_api_error(self):
        return ['IMPLEMENTATION_ERROR', self.klass, self.func]        

    def __str__(self):
        return 'IMPLEMENTATION_ERROR: %s %s' % (self.klass, self.func)

class VLANTagInvalid(XendAPIError):
    def __init__(self, vlan):
        XendAPIError.__init__(self)
        self.vlan = vlan

    def get_api_error(self):
        return ['VLAN_TAG_INVALID', self.vlan]

    def __str__(self):
        return 'VLAN_TAG_INVALID: %s' % self.vlan
    
XEND_ERROR_AUTHENTICATION_FAILED = ('ELUSER', 'Authentication Failed')
XEND_ERROR_SESSION_INVALID       = ('EPERMDENIED', 'Session Invalid')
XEND_ERROR_DOMAIN_INVALID        = ('EINVALIDDOMAIN', 'Domain Invalid')
XEND_ERROR_HOST_INVALID          = ('EINVALIDHOST', 'Host Invalid')
XEND_ERROR_HOST_RUNNING          = ('EHOSTRUNNING', 'Host is still Running')
XEND_ERROR_HOST_CPU_INVALID      = ('EHOSTCPUINVALID', 'Host CPU Invalid')
XEND_ERROR_UNSUPPORTED           = ('EUNSUPPORTED', 'Method Unsupported')
XEND_ERROR_VM_INVALID            = ('EVMINVALID', 'VM Invalid')
XEND_ERROR_VBD_INVALID           = ('EVBDINVALID', 'VBD Invalid')
XEND_ERROR_VIF_INVALID           = ('EVIFINVALID', 'VIF Invalid')
XEND_ERROR_VTPM_INVALID          = ('EVTPMINVALID', 'VTPM Invalid')
XEND_ERROR_VDI_INVALID           = ('EVDIINVALID', 'VDI Invalid')
XEND_ERROR_SR_INVALID           = ('ESRINVALID', 'SR Invalid')
XEND_ERROR_TODO                  = ('ETODO', 'Lazy Programmer Error')
