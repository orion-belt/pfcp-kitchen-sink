// Copyright 2019-2020 Orange
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// limitations under the License.

// Package pfcp implements subset of PFCP protocol
// as defined on 3GPP TS 29.244
package pfcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

//go:generate enumer -type=ApplyAction  -yaml
//go:generate enumer -type=OuterHeaderCreationMask -yaml
//go:generate enumer -type=OuterHeaderRemoval -yaml
//go:generate enumer -type=MessageType -yaml

const (
	MaxSize       = 1024
	PFCP_VERSION  = 1
	PFCP_UDP_PORT = 8805
)

type IEType uint16

// IE types
const (
	NodeIDIEType                     IEType = 60
	RecoveryTimestampIEType          IEType = 96
	CauseIEType                      IEType = 19
	FSEIDIETYPE                      IEType = 57
	CreatePDRIEType                  IEType = 1
	PDRIDIEType                      IEType = 56
	PrecedenceIEType                 IEType = 29
	PDIIEType                        IEType = 2
	OuterHeaderRemovelIEType         IEType = 95
	FARIDIEType                      IEType = 108
	SourceInterfaceIEType            IEType = 20
	FTEIDIEType                      IEType = 21
	ApplicationIDIEType              IEType = 24
	NetworkInstanceIEType            IEType = 22
	SDFFilterIEType                  IEType = 23
	UEIPAddressIEType                IEType = 93
	CreateFARIEType                  IEType = 3
	ApplyActionIEType                IEType = 44
	ForwardingParametersIEType       IEType = 4
	DestinationInterfaceIEType       IEType = 42
	ForwardingPolicyIEType           IEType = 41
	RedirectInformationIEType        IEType = 38
	OuterHeaderCreationIEType        IEType = 84
	UPFunctionFeaturesIETYpe         IEType = 43
	UpdateFARIEType                  IEType = 10
	UpdateForwardingParametersIEType IEType = 11
)

type MessageType uint8

//Message types
const (
	HeartbeatRequest            MessageType = 1
	HeartbeatResponse           MessageType = 2
	AssociationSetupRequest     MessageType = 5
	AssociationSetupResponse    MessageType = 6
	SessionEtablismentRequest   MessageType = 50
	SessionEtablismentResponse  MessageType = 51
	SessionModificationRequest  MessageType = 52
	SessionModificationResponse MessageType = 53
	SessionDeletionRequest      MessageType = 54
	SessionDeletionResponse     MessageType = 55
)

func newTLVBuffer(tag IEType, length uint16) (b []byte, n int) {
	b = make([]byte, MaxSize)
	binary.BigEndian.PutUint16(b, uint16(tag))
	binary.BigEndian.PutUint16(b[2:], length)
	return b, 4
}

func setTLVLength(b []byte, n int) {
	binary.BigEndian.PutUint16(b[2:], uint16(n-4))
}

func newTLVUint8(tag IEType, v uint8) []byte {
	b := make([]byte, 5)
	binary.BigEndian.PutUint16(b, uint16(tag))
	binary.BigEndian.PutUint16(b[2:], 1)
	b[4] = v
	return b
}
func newTLVUint16(tag IEType, v uint16) []byte {
	b := make([]byte, 6)
	binary.BigEndian.PutUint16(b, uint16(tag))
	binary.BigEndian.PutUint16(b[2:], 2)
	binary.BigEndian.PutUint16(b[4:], v)
	return b
}

func newTLVUint32(tag IEType, v uint32) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b, uint16(tag))
	binary.BigEndian.PutUint16(b[2:], 4)
	binary.BigEndian.PutUint32(b[4:], v)
	return b
}

func newTLVString(tag IEType, s string) []byte {
	b := make([]byte, 4+len(s))
	binary.BigEndian.PutUint16(b, uint16(tag))
	binary.BigEndian.PutUint16(b[2:], uint16(len(s)))
	copy(b[4:], s)
	return b
}

// See clause 3.1 of IETF RFC 1035
func encodeDNSName(data []byte, name string) int {
	l := 0
	for i := range name {
		if name[i] == '.' {
			data[i-l] = byte(l)
			l = 0
		} else {
			// skip one to write the length
			data[i+1] = name[i]
			l++
		}
	}

	if len(name) == 0 {
		data[0] = 0x00 // terminal
		return 1
	}

	// length for final portion
	data[len(name)-l] = byte(l)
	// data[len(name)+1] = 0x00 // terminal
	return len(name) + 1
}

func decodeDNSName(data []byte) (string, error) {
	result := make([]byte, 0)
	i := 0
	inputLen := len(data)
	if inputLen == 0 {
		return "", nil
	}
	for {
		l := int(data[i])
		i++
		if l&0xC0 != 0 {
			return "", errors.New("bad label length > 63")
		}
		if l == 0 { // should not occur
			break
		}
		if i+l > inputLen {
			return "", errors.New("bad label length")
		}
		result = append(result, data[i:i+l]...)
		i += l
		if i < inputLen {
			result = append(result, '.')
		} else {
			break
		}
	}
	return string(result), nil
}

func newTLVDNSName(tag IEType, s string) []byte {
	b := make([]byte, MaxSize)
	binary.BigEndian.PutUint16(b, uint16(tag))
	n := encodeDNSName(b[4:], s)
	binary.BigEndian.PutUint16(b[2:], uint16(n))
	return b[:n+4]
}

type PFCPInformationElement interface {
	fmt.Stringer
	Type() IEType
	Marshal() []byte
	UnMarshal(in []byte)
}

type NodeIDType uint8

const (
	NodeID_IPV4 NodeIDType = 0
	NodeID_IPV6 NodeIDType = 1
	NodeID_FQDN NodeIDType = 2
)

type NodeID struct {
	nodeIDType NodeIDType
	ipAddr     net.IP
	fqdn       string
}

func NewNodeID(val string) *NodeID {
	var n = NodeID{}
	n.ipAddr = net.ParseIP(val)
	if n.ipAddr != nil {
		if n.ipAddr.To4() != nil {
			n.nodeIDType = NodeID_IPV4
			n.ipAddr = n.ipAddr.To4()
		} else {
			n.nodeIDType = NodeID_IPV6
		}
	} else {
		n.nodeIDType = NodeID_FQDN
		n.fqdn = val
	}
	return &n
}

func (node *NodeID) String() string {
	if node.nodeIDType == NodeID_FQDN {
		return fmt.Sprintf("NodeID[%s]", node.fqdn)
	}
	return fmt.Sprintf("NodeID[%s]", node.ipAddr)
}

func (ie *NodeID) Type() IEType {
	return NodeIDIEType
}
func (node *NodeID) Marshal() []byte {
	b, n := newTLVBuffer(NodeIDIEType, 0)
	b[n] = byte(node.nodeIDType)
	n++
	switch node.nodeIDType {
	case NodeID_IPV4, NodeID_IPV6:
		n += copy(b[n:], node.ipAddr)
	case NodeID_FQDN:
		n += encodeDNSName(b[n:], node.fqdn)
	}
	setTLVLength(b, n)
	return b[:n]
}

func (node *NodeID) UnMarshal(b []byte) {
	node.nodeIDType = NodeIDType(b[0])
	if node.nodeIDType == NodeID_IPV4 {
		node.ipAddr = make([]byte, 4)
		copy(node.ipAddr, b[1:])
	} else if node.nodeIDType == NodeID_IPV6 {
		node.ipAddr = make([]byte, 16)
		copy(node.ipAddr, b[1:])
	} else {
		var err error
		node.fqdn, err = decodeDNSName(b[1:])
		if err != nil {
			fmt.Printf("NodeID.UnMarshall: wrong fqdn %v\n", err)
		}
	}
}

const (
	FSEID_V6 = 1 << 0
	FSEID_V4 = 1 << 1
)

type FSEID struct {
	ip4  net.IP
	ip6  net.IP
	seid uint64
}

func NewFSEID(ip string, seid uint64) *FSEID {
	return &FSEID{ip4: net.ParseIP(ip).To4(), seid: seid}
}

func (f *FSEID) String() string {
	return fmt.Sprintf("FSEID[seid=%d,ip=%s]", f.seid, f.ip4)
}

func (ie *FSEID) Type() IEType {
	return FSEIDIETYPE
}

func (f *FSEID) Marshal() []byte {
	b, n := newTLVBuffer(FSEIDIETYPE, 0)
	if f.ip4 != nil {
		b[n] |= FSEID_V4
	}
	if f.ip6 != nil {
		b[n] |= FSEID_V6
	}
	n++
	binary.BigEndian.PutUint64(b[n:], f.seid)
	n += 8
	if f.ip4 != nil {
		n += copy(b[n:], f.ip4)
	}
	if f.ip6 != nil {
		n += copy(b[n:], f.ip6)
	}
	setTLVLength(b, n)
	return b[:n]
}

func (f *FSEID) UnMarshal(b []byte) {
	// XX ipv6 b[0]
	n := 1
	f.seid = binary.BigEndian.Uint64(b[n:])
	n += 8
	f.ip4 = make([]byte, 4)
	copy(f.ip4, b[n:])
}

func (f *FSEID) SEID() uint64 {
	return f.seid
}

type RecoveryTimestamp struct {
	timestamp time.Time
}

func NewRecoveryTimestamp(t time.Time) *RecoveryTimestamp {
	var rt = RecoveryTimestamp{timestamp: t}
	return &rt
}

func (r *RecoveryTimestamp) String() string {
	return fmt.Sprintf("RecoveryTimestamp[%s]", r.timestamp)
}

func (ie *RecoveryTimestamp) Type() IEType {
	return RecoveryTimestampIEType
}

func (r *RecoveryTimestamp) Marshal() []byte {
	b, n := newTLVBuffer(RecoveryTimestampIEType, 4)
	binary.BigEndian.PutUint32(b[n:], uint32(r.timestamp.Unix()))
	n += 4
	return b[:n]
}

func (r *RecoveryTimestamp) UnMarshal(b []byte) {
	ts := binary.BigEndian.Uint32(b)
	r.timestamp = time.Unix(int64(ts), 0)
}

type Cause uint8

// cause values
const (
	RequestAccepted                   Cause = 1
	RequestRejected                   Cause = 64
	SessionContextNotFound            Cause = 65
	MandatoryIEMissing                Cause = 66
	ConditionalIEMissing              Cause = 67
	InvalidLength                     Cause = 68
	MandatoryIEIncorrect              Cause = 69
	InvalidForwardPolicy              Cause = 70
	InvalidFTEIDAllocationOption      Cause = 71
	NoEstablishedPFCPAssociation      Cause = 72
	RuleCreationOrModificationFailure Cause = 73
	PFCPEntityInCongestion            Cause = 74
	NoResourcesAvailable              Cause = 75
	ServiceNotSupported               Cause = 76
	SystemFailure                     Cause = 77
	RedirectionRequested              Cause = 78
)

func (c Cause) String() string {
	switch c {
	case RequestAccepted:
		return "Request accepted"
	case RequestRejected:
		return "Request rejected"
	case SessionContextNotFound:
		return "Session context not found"
	case MandatoryIEMissing:
		return "Mandatory IE missing"
	case ConditionalIEMissing:
		return "Conditional IE missing"
	case InvalidLength:
		return "Invalid length"
	case MandatoryIEIncorrect:
		return "Mandatory IE incorrect"
	case InvalidForwardPolicy:
		return "Invalid forward policy"
	case InvalidFTEIDAllocationOption:
		return "Invalid F-TEID allocation option"
	case NoEstablishedPFCPAssociation:
		return "No established PFCP association"
	case RuleCreationOrModificationFailure:
		return "Rule creation/modification failure"
	case PFCPEntityInCongestion:
		return "PFCP entity in congestion"
	case NoResourcesAvailable:
		return "No resources available"
	case ServiceNotSupported:
		return "Service not supported"
	case SystemFailure:
		return "System failure"
	case RedirectionRequested:
		return "Redirection requested"
	default:
		return "Unknown cause value"
	}
}

//CauseIE information element
type CauseIE struct {
	value Cause
}

func NewCauseIE(value Cause) *CauseIE {
	return &CauseIE{value: value}
}

func (c *CauseIE) String() string {
	return c.value.String()
}

func (ie *CauseIE) Type() IEType {
	return CauseIEType
}

func (c *CauseIE) Marshal() []byte {
	b, n := newTLVBuffer(CauseIEType, 1)
	b[n] = byte(c.value)
	n++
	return b[:n]
}

func (c *CauseIE) UnMarshal(b []byte) {
	c.value = Cause(b[0])
}

// PDR ID IE
type PdrID uint16

func (pdr *PdrID) String() string {
	return strconv.Itoa(int(uint16(*pdr)))
}

func (ie *PdrID) Type() IEType {
	return PDRIDIEType
}

func (pdr *PdrID) Marshal() []byte {
	b, n := newTLVBuffer(PDRIDIEType, 2)
	binary.BigEndian.PutUint16(b[n:], uint16(*pdr))
	n += 2
	return b[:n]
}

func (pdr *PdrID) UnMarshal(b []byte) {
	*pdr = PdrID(binary.BigEndian.Uint16(b))
}

// Precedence IE
type Precedence uint32

func (pre *Precedence) String() string {
	return strconv.Itoa(int(*pre))
}

func (ie *Precedence) Type() IEType {
	return PrecedenceIEType
}

func (pre *Precedence) Marshal() []byte {
	b, n := newTLVBuffer(PrecedenceIEType, 4)
	binary.BigEndian.PutUint32(b[n:], uint32(*pre))
	n += 4
	return b[:n]
}

func (pre *Precedence) UnMarshal(b []byte) {
	*pre = Precedence(binary.BigEndian.Uint32(b))
}

// FarID IE
type FarID uint32

func (far *FarID) String() string {
	return strconv.Itoa(int(*far))
}

func (ie *FarID) Type() IEType {
	return FARIDIEType
}

func (far *FarID) Marshal() []byte {
	b, n := newTLVBuffer(FARIDIEType, 4)
	binary.BigEndian.PutUint32(b[n:], uint32(*far))
	n += 4
	return b[:n]
}

func (far *FarID) UnMarshal(b []byte) {
	*far = FarID(binary.BigEndian.Uint32(b))
}

// Outer Header Removal IE
type OuterHeaderRemoval uint8

const (
	OUTER_HEADER_GTPU_UDP_IPV4 OuterHeaderRemoval = iota
	OUTER_HEADER_GTPU_UDP_IPV6
	OUTER_HEADER_UDP_IPV4
	OUTER_HEADER_UDP_IPV46
)

func (ie *OuterHeaderRemoval) Type() IEType {
	return OuterHeaderRemovelIEType
}

func (ohr *OuterHeaderRemoval) Marshal() []byte {
	b, n := newTLVBuffer(OuterHeaderRemovelIEType, 1)
	b[n] = byte(*ohr)
	n += 1
	return b[:n]
}

func (ohr *OuterHeaderRemoval) UnMarshal(b []byte) {
	*ohr = OuterHeaderRemoval(b[0])
}

// Create PDR IE
type CreatePdr struct {
	PdrID              PdrID               `yaml:"pdrID"`
	Precedence         Precedence          `yaml:"precedence"`
	Pdi                *PDI                `yaml:"pdi"`
	OuterHeaderRemoval *OuterHeaderRemoval `yaml:"outerHeaderRemoval,omitempty"`
	FarID              *FarID              `yaml:"farID"`
}

func NewCreatePdr(pdrID PdrID, precedence Precedence, pdi *PDI) *CreatePdr {
	return &CreatePdr{PdrID: pdrID, Precedence: precedence, Pdi: pdi}
}

func (c *CreatePdr) String() string {
	return fmt.Sprintf("CreatePDR[pdrId=%d,precedence=%d,ohr=%v,farId=%v,pdi=%v]", c.PdrID, c.Precedence, c.OuterHeaderRemoval, c.FarID, c.Pdi)
}

func (c *CreatePdr) SetOuterHeaderRemoval(f OuterHeaderRemoval) {
	c.OuterHeaderRemoval = &f
}

func (c *CreatePdr) SetFARID(id FarID) {
	c.FarID = &id
}

func (ie *CreatePdr) Type() IEType {
	return CreatePDRIEType
}

func (c *CreatePdr) Marshal() []byte {
	b, n := newTLVBuffer(CreatePDRIEType, 0)
	n += copy(b[n:], newTLVUint16(PDRIDIEType, uint16(c.PdrID)))
	n += copy(b[n:], newTLVUint32(PrecedenceIEType, uint32(c.Precedence)))
	n += copy(b[n:], c.Pdi.Marshal())
	if c.OuterHeaderRemoval != nil {
		n += copy(b[n:], newTLVUint8(OuterHeaderRemovelIEType, uint8(*c.OuterHeaderRemoval)))
	}
	if c.FarID != nil {
		n += copy(b[n:], newTLVUint32(FARIDIEType, uint32(*c.FarID)))
	}
	setTLVLength(b, n)
	return b[:n]
}

func (c *CreatePdr) UnMarshal(b []byte) {
	n := 0
	inputLen := len(b)
	for {
		ieLen, ie, err := DecodePFCPInformationElement(b[n:])
		if err != nil {
			break //XX
		}
		if ie != nil {
			switch ie.(type) {
			case *PdrID:
				c.PdrID = *ie.(*PdrID)
			case *Precedence:
				c.Precedence = *ie.(*Precedence)
			case *OuterHeaderRemoval:
				c.OuterHeaderRemoval = ie.(*OuterHeaderRemoval)
			case *FarID:
				c.FarID = ie.(*FarID)
			case *PDI:
				c.Pdi = ie.(*PDI)
			}
		}
		n += ieLen
		if n >= inputLen {
			break
		}
	}
}

// Network Instance IE
type NetworkInstance string

func (nwi *NetworkInstance) String() string {
	return string(*nwi)
}

func (ie *NetworkInstance) Type() IEType {
	return NetworkInstanceIEType
}

func (nwi *NetworkInstance) Marshal() []byte {
	return newTLVDNSName(NetworkInstanceIEType, string(*nwi))
}

func (nwi *NetworkInstance) UnMarshal(b []byte) {
	s, err := decodeDNSName(b)
	if err != nil {
		fmt.Printf("Unable to decode Network Instance %v", err)
		return
	}
	*nwi = NetworkInstance(s)
}

// Source Interface IE
type SourceInterface uint8

const (
	SI_Access       SourceInterface = iota
	SI_Core         SourceInterface = iota
	SI_SGiLAN       SourceInterface = iota
	SI_CPFuntion    SourceInterface = iota
	SI_5GVNInternal SourceInterface = iota
)

func (ie *SourceInterface) Type() IEType {
	return SourceInterfaceIEType
}

func (i *SourceInterface) String() string {
	s, _ := (*i).MarshalYAML()
	return s.(string)
}

func (i SourceInterface) MarshalYAML() (interface{}, error) {
	switch i {
	case SI_Access:
		return "Access", nil
	case SI_Core:
		return "Core", nil
	case SI_SGiLAN:
		return "SGiLAN", nil
	case SI_CPFuntion:
		return "CPFunction", nil
	case SI_5GVNInternal:
		return "5GVNInternal", nil
	}
	return nil, fmt.Errorf("Wrong source interface value: %v", i)
}

// UnmarshalYAML implements a YAML Unmarshaler for DestinationInterface
func (i *SourceInterface) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	switch s {
	case "Access":
		*i = SI_Access
	case "Core":
		*i = SI_Core
	case "SGiLAN":
		*i = SI_SGiLAN
	case "CPFunction":
		*i = SI_CPFuntion
	case "5GVNInternal":
		*i = SI_5GVNInternal
	default:
		return fmt.Errorf("Wrong source interface value: %v", s)
	}
	return nil
}

func (si *SourceInterface) Marshal() []byte {
	return newTLVUint8(SourceInterfaceIEType, uint8(*si))
}

func (si *SourceInterface) UnMarshal(b []byte) {
	*si = SourceInterface(b[0] & 0x0F)
}

// Application ID IE
type ApplicationID string

func (id *ApplicationID) String() string {
	return string(*id)
}

func (ie *ApplicationID) Type() IEType {
	return ApplicationIDIEType
}

func (id *ApplicationID) Marshal() []byte {
	return newTLVString(ApplicationIDIEType, string(*id))
}

func (id *ApplicationID) UnMarshal(b []byte) {
	bytes := make([]byte, len(b))
	copy(bytes, b)
	*id = ApplicationID(bytes)
}

//TODO multiple SDFFilter per PDI
type PDI struct {
	SourceInterface SourceInterface  `yaml:"sourceInterface"`
	LocalFTEID      *FTEID           `yaml:"localFTEID,omitempty"`
	NetworkInstance *NetworkInstance `yaml:"networkInstance,omitempty"`
	UeIPAddress     *UEIPAddress     `yaml:"ueIPAddress,omitempty"`
	SdfFilter       *SDFFilter       `yaml:"sdfFilter,omitempty"`
	ApplicationID   *ApplicationID   `yaml:"applicationID,omitempty"`
}

func NewPDI(sourceInterface SourceInterface) *PDI {
	return &PDI{SourceInterface: sourceInterface}
}

func (pdi *PDI) SetLocalFTEID(fteid *FTEID) {
	pdi.LocalFTEID = fteid
}

func (pdi *PDI) SetNetworkInstance(networkInstance string) {
	nwi := NetworkInstance(networkInstance)
	pdi.NetworkInstance = &nwi
}

func (pdi *PDI) SetUeIPAddress(addr *UEIPAddress) {
	pdi.UeIPAddress = addr
}

func (pdi *PDI) SetSDFFilter(filter *SDFFilter) {
	pdi.SdfFilter = filter
}

func (pdi *PDI) SetApplicationID(appID string) {
	id := ApplicationID(appID)
	pdi.ApplicationID = &id
}

func (ie *PDI) Type() IEType {
	return PDIIEType
}

func (pdi *PDI) Marshal() []byte {
	b, n := newTLVBuffer(PDIIEType, 0)
	n += copy(b[n:], pdi.SourceInterface.Marshal())
	if pdi.LocalFTEID != nil {
		n += copy(b[n:], pdi.LocalFTEID.Marshal())
	}
	if pdi.NetworkInstance != nil {
		n += copy(b[n:], pdi.NetworkInstance.Marshal())
	}
	if pdi.UeIPAddress != nil {
		n += copy(b[n:], pdi.UeIPAddress.Marshal())
	}
	if pdi.SdfFilter != nil {
		n += copy(b[n:], pdi.SdfFilter.Marshal())
	}
	if pdi.ApplicationID != nil {
		n += copy(b[n:], pdi.ApplicationID.Marshal())
	}
	setTLVLength(b, n)
	return b[:n]
}

func (pdi *PDI) UnMarshal(b []byte) {
	n := 0
	inputLen := len(b)
	for {
		ieLen, ie, err := DecodePFCPInformationElement(b[n:])
		if err != nil {
			break //XX
		}
		if ie != nil {
			switch ie.(type) {
			case *SourceInterface:
				pdi.SourceInterface = *ie.(*SourceInterface)
			case *FTEID:
				pdi.LocalFTEID = ie.(*FTEID)
			case *UEIPAddress:
				pdi.UeIPAddress = ie.(*UEIPAddress)
			case *SDFFilter:
				pdi.SdfFilter = ie.(*SDFFilter)
			case *NetworkInstance:
				pdi.NetworkInstance = ie.(*NetworkInstance)
			case *ApplicationID:
				pdi.ApplicationID = ie.(*ApplicationID)
			}
		}
		n += ieLen
		if n >= inputLen {
			break
		}
	}
}

func (pdi *PDI) String() string {
	return fmt.Sprintf("%+v", *pdi)
	//return fmt.Sprintf("PDI[si=%v,fteid=%v,nwi=%v,sdf=%v,ue_ip=%v]", pdi.SourceInterface, pdi.LocalFTEID, pdi.NetworkInstance, pdi.SdfFilter, pdi.UeIPAddress)
}

//F-TEID IE

const (
	FTEID_IPV4 = 1 << 0
	FTEID_IPV6 = 1 << 1
	FTEID_CH   = 1 << 2
	FTEID_CHID = 1 << 3
)

type FTEID struct {
	flags    uint8
	Teid     uint32 `yaml:"teid"`
	Ip4      net.IP `yaml:"ip4"`
	ip6      net.IP
	chooseID uint8
}

func NewFTEID(ip4 net.IP, teid uint32) *FTEID {
	r := new(FTEID)
	r.Teid = teid
	r.Ip4 = ip4
	r.flags = FTEID_IPV4
	return r
}

func (ie *FTEID) Type() IEType {
	return FTEIDIEType
}

func (f *FTEID) Marshal() []byte {
	b, n := newTLVBuffer(FTEIDIEType, 0)
	if f.flags == 0 && f.Ip4 != nil {
		f.flags = FTEID_IPV4
	}
	b[n] = f.flags
	n++
	binary.BigEndian.PutUint32(b[n:], f.Teid)
	n += 4
	if f.Ip4 != nil {
		n += copy(b[n:], f.Ip4.To4())
	}
	if f.ip6 != nil {
		n += copy(b[n:], f.ip6.To16())
	}
	if f.flags&FTEID_CHID != 0 {
		b[n] = f.chooseID
		n++
	}
	setTLVLength(b, n)
	return b[:n]
}

func (f *FTEID) UnMarshal(b []byte) {
	n := 0
	f.flags = b[n]
	n++
	f.Teid = binary.BigEndian.Uint32(b[n:])
	n += 4
	if f.flags&FTEID_IPV4 != 0 {
		f.Ip4 = make([]byte, 4)
		copy(f.Ip4, b[n:])
		n += 4
	}
	if f.flags&FTEID_IPV6 != 0 {
		f.ip6 = make([]byte, 16)
		copy(f.ip6, b[n:])
		n += 16
	}
	if f.flags&FTEID_CHID != 0 {
		f.chooseID = b[n]
		n++
	}
}

func (f *FTEID) String() string {
	return fmt.Sprintf("FTEID[teid=%d,ip=%v]", f.Teid, f.Ip4)
}

const (
	UE_IP_ADDRESS_V6             = 1 << 0
	UE_IP_ADDRESS_V4             = 1 << 1
	UE_IP_ADDRESS_IS_DESTINATION = 1 << 2
)

type UEIPAddress struct {
	IsDestination bool   `yaml:"isDestination"`
	Ip4           net.IP `yaml:",omitempty"`
	Ip6           net.IP `yaml:",omitempty"`
}

func NewUEIPAddress(ip4 net.IP, isDestination bool) *UEIPAddress {
	r := new(UEIPAddress)
	r.Ip4 = ip4
	r.IsDestination = isDestination
	return r
}

func (ie *UEIPAddress) Type() IEType {
	return UEIPAddressIEType
}

func (ueAddr *UEIPAddress) Marshal() []byte {
	b, n := newTLVBuffer(UEIPAddressIEType, 0)
	var flags uint8
	if ueAddr.IsDestination {
		flags |= UE_IP_ADDRESS_IS_DESTINATION
	}
	if ueAddr.Ip4 != nil {
		flags |= UE_IP_ADDRESS_V4
	}
	if ueAddr.Ip6 != nil {
		flags |= UE_IP_ADDRESS_V6
	}
	b[n] = flags
	n++
	if ueAddr.Ip4 != nil {
		n += copy(b[n:], ueAddr.Ip4.To4())
	}
	if ueAddr.Ip6 != nil {
		n += copy(b[n:], ueAddr.Ip6.To16())
	}
	setTLVLength(b, n)
	return b[:n]
}

func (ueAddr *UEIPAddress) UnMarshal(b []byte) {
	n := 0
	flags := b[n]
	n++
	ueAddr.IsDestination = (flags & UE_IP_ADDRESS_IS_DESTINATION) != 0
	if flags&UE_IP_ADDRESS_V4 != 0 {
		ueAddr.Ip4 = make([]byte, 4)
		copy(ueAddr.Ip4, b[n:])
		n += 4
	}
	if flags&UE_IP_ADDRESS_V6 != 0 {
		ueAddr.Ip6 = make([]byte, 16)
		copy(ueAddr.Ip6, b[n:])
		n += 16
	}
}

func (ueAddr *UEIPAddress) String() string {
	return fmt.Sprintf("UEIPAddress[dest=%v,ip=%v]", ueAddr.IsDestination, ueAddr.Ip4)
}

const (
	SDF_FILTER_FD = 1 << 0
)

type SDFFilter struct {
	flags           uint8
	FlowDescription string `yaml:"flowDescription"`
}

func NewSDFFilter(flowDescription string) *SDFFilter {
	return &SDFFilter{flags: SDF_FILTER_FD, FlowDescription: flowDescription}
}

func (sdfFilter *SDFFilter) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var filter struct {
		FlowDescription string `yaml:"flowDescription"`
	}
	if err := unmarshal(&filter); err != nil {
		return err
	}
	sdfFilter.flags = SDF_FILTER_FD
	sdfFilter.FlowDescription = filter.FlowDescription
	return nil
}

func (ie *SDFFilter) Type() IEType {
	return SDFFilterIEType
}

func (sdfFilter *SDFFilter) Marshal() []byte {
	b, n := newTLVBuffer(SDFFilterIEType, 0)
	b[n] = sdfFilter.flags
	n += 2
	if sdfFilter.flags&SDF_FILTER_FD != 0 {
		binary.BigEndian.PutUint16(b[n:], uint16(len(sdfFilter.FlowDescription)))
		n += 2
		n += copy(b[n:], sdfFilter.FlowDescription)
	}
	setTLVLength(b, n)
	return b[:n]
}

func (sdfFilter *SDFFilter) UnMarshal(b []byte) {
	n := 0
	sdfFilter.flags = uint8(b[n])
	n++
	if sdfFilter.flags&SDF_FILTER_FD != 0 {
		n++ // skip spare byte
		len := binary.BigEndian.Uint16(b[n:])
		n += 2
		bytes := make([]byte, len)
		copy(bytes, b[n:])
		sdfFilter.FlowDescription = string(bytes)
		n += int(len)
	} else {
		fmt.Printf("Unsupported SDF filter type flags=%x", sdfFilter.flags)
	}
}

func (sdfFilter *SDFFilter) String() string {
	return fmt.Sprintf("SDFFilter[flowDesc=\"%s\"", sdfFilter.FlowDescription)
}

// ApplyAction IE
type ApplyAction uint8

// actions the UP is required to apply to packets
const (
	Drop      ApplyAction = 1 << iota
	Forward   ApplyAction = 1 << iota
	Buffer    ApplyAction = 1 << iota
	NotifyCP  ApplyAction = 1 << iota
	Duplicate ApplyAction = 1 << iota
)

func (ie *ApplyAction) Type() IEType {
	return ApplyActionIEType
}

func (action *ApplyAction) Marshal() []byte {
	return newTLVUint8(ApplyActionIEType, uint8(*action))
}

func (action *ApplyAction) UnMarshal(b []byte) {
	*action = ApplyAction(b[0])
}

// CreateFAR IE
type CreateFAR struct {
	FarID                FarID                 `yaml:"farID"`
	ApplyAction          ApplyAction           `yaml:"applyAction"`
	ForwardingParameters *ForwardingParameters `yaml:"forwardingParameters,omitempty"`
}

func NewCreateFar(id uint32, applyAction ApplyAction) *CreateFAR {
	r := &CreateFAR{FarID: FarID(id), ApplyAction: applyAction}
	return r
}
func (far *CreateFAR) String() string {
	return fmt.Sprintf("CreateFar%+v", *far)
}

func (far *CreateFAR) SetForwardingParameters(params *ForwardingParameters) {
	far.ForwardingParameters = params
}

func (ie *CreateFAR) Type() IEType {
	return CreateFARIEType
}

func (far *CreateFAR) Marshal() []byte {
	b, n := newTLVBuffer(CreateFARIEType, 0)
	n += copy(b[n:], far.FarID.Marshal())
	n += copy(b[n:], far.ApplyAction.Marshal())
	if far.ForwardingParameters != nil {
		n += copy(b[n:], far.ForwardingParameters.Marshal())
	}
	setTLVLength(b, n)
	return b[:n]
}

func (far *CreateFAR) UnMarshal(b []byte) {
	n := 0
	inputLen := len(b)
	for {
		ieLen, ie, err := DecodePFCPInformationElement(b[n:])
		if err != nil {
			break //XX
		}
		if ie != nil {
			switch ie.(type) {
			case *FarID:
				far.FarID = *ie.(*FarID)
			case *ApplyAction:
				far.ApplyAction = *ie.(*ApplyAction)
			case *ForwardingParameters:
				far.ForwardingParameters = ie.(*ForwardingParameters)
			}
		}
		n += ieLen
		if n >= inputLen {
			break
		}
	}
}

// UpdateFAR IE
type UpdateFAR struct {
	FarID                      FarID                       `yaml:"farID"`
	ApplyAction                *ApplyAction                `yaml:"applyAction,omitempty"`
	UpdateForwardingParameters *UpdateForwardingParameters `yaml:"updateForwardingParameters,omitempty"`
}

func NewUpdateFAR(id uint32) *UpdateFAR {
	r := &UpdateFAR{FarID: FarID(id)}
	return r
}
func (far *UpdateFAR) String() string {
	return fmt.Sprintf("UpdateFar%+v", *far)
}

func (far *UpdateFAR) SetUpdateForwardingParameters(params *UpdateForwardingParameters) {
	far.UpdateForwardingParameters = params
}

func (far *UpdateFAR) SetApplyAction(action *ApplyAction) {
	far.ApplyAction = action
}

func (ie *UpdateFAR) Type() IEType {
	return UpdateFARIEType
}

func (far *UpdateFAR) Marshal() []byte {
	b, n := newTLVBuffer(UpdateFARIEType, 0)
	n += copy(b[n:], far.FarID.Marshal())
	if far.ApplyAction != nil {
		n += copy(b[n:], far.ApplyAction.Marshal())
	}
	if far.UpdateForwardingParameters != nil {
		n += copy(b[n:], far.UpdateForwardingParameters.Marshal())
	}
	setTLVLength(b, n)
	return b[:n]
}

func (far *UpdateFAR) UnMarshal(b []byte) {
	n := 0
	inputLen := len(b)
	for {
		ieLen, ie, err := DecodePFCPInformationElement(b[n:])
		if err != nil {
			break //XX
		}
		if ie != nil {
			switch ie.(type) {
			case *FarID:
				far.FarID = *ie.(*FarID)
			case *ApplyAction:
				far.ApplyAction = ie.(*ApplyAction)
			case *UpdateForwardingParameters:
				far.UpdateForwardingParameters = ie.(*UpdateForwardingParameters)
			}
		}
		n += ieLen
		if n >= inputLen {
			break
		}
	}
}

type DestinationInterface uint8

const (
	DI_Access     DestinationInterface = iota
	DI_Core       DestinationInterface = iota
	DI_SGiLAN     DestinationInterface = iota
	DI_CPFuntion  DestinationInterface = iota
	DI_LIFunction DestinationInterface = iota
)

func (ie *DestinationInterface) Type() IEType {
	return DestinationInterfaceIEType
}

func (di *DestinationInterface) Marshal() []byte {
	return newTLVUint8(DestinationInterfaceIEType, uint8(*di))
}

func (di *DestinationInterface) UnMarshal(b []byte) {
	*di = DestinationInterface(b[0] & 0x0F)
}

func (i *DestinationInterface) String() string {
	s, _ := (*i).MarshalYAML()
	return s.(string)
}

func (i DestinationInterface) MarshalYAML() (interface{}, error) {
	switch i {
	case DI_Access:
		return "Access", nil
	case DI_Core:
		return "Core", nil
	case DI_SGiLAN:
		return "SGiLAN", nil
	case DI_CPFuntion:
		return "CPFunction", nil
	case DI_LIFunction:
		return "LIFunction", nil
	}
	return nil, fmt.Errorf("Wrong destination interface value: %v", i)
}

// UnmarshalYAML implements a YAML Unmarshaler for DestinationInterface
func (i *DestinationInterface) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	switch s {
	case "Access":
		*i = DI_Access
	case "Core":
		*i = DI_Core
	case "SGiLAN":
		*i = DI_SGiLAN
	case "CPFunction":
		*i = DI_CPFuntion
	case "LIFunction":
		*i = DI_LIFunction
	default:
		return fmt.Errorf("Wrong destination interface value: %v", s)
	}
	return nil
}

type RedirectAddressType uint8

const (
	IPV4 RedirectAddressType = iota
	IPV6 RedirectAddressType = iota
	URL  RedirectAddressType = iota
	SIP  RedirectAddressType = iota
)

// Redirect Information IE
type RedirectInformation struct {
	RedirectAddressType RedirectAddressType `yaml:"redirectAddressType"`
	RedirectAddress     string              `yaml:"redirectAddress"`
}

func (ri *RedirectInformation) String() string {
	return fmt.Sprintf("RedirectInformation%+v", *ri)
}

func (ie *RedirectInformation) Type() IEType {
	return RedirectInformationIEType
}

func (ri *RedirectInformation) Marshal() []byte {
	b, n := newTLVBuffer(RedirectInformationIEType, 0)
	b[n] = uint8(ri.RedirectAddressType)
	n++
	binary.BigEndian.PutUint16(b[n:], uint16(len(ri.RedirectAddress)))
	n += 2
	n += copy(b[n:], ri.RedirectAddress)
	setTLVLength(b, n)
	return b[:n]
}

func (ri *RedirectInformation) UnMarshal(b []byte) {
	n := 0
	ri.RedirectAddressType = RedirectAddressType(b[n] & 0x0F)
	n++
	len := binary.BigEndian.Uint16(b[n:])
	n += 2
	bytes := make([]byte, len)
	copy(bytes, b[n:])
	ri.RedirectAddress = string(bytes)
}

type OuterHeaderCreationMask uint8

const (
	OUTER_HEADER_CREATION_GTPU_UDP_IPV4 OuterHeaderCreationMask = 1 << 0
	OUTER_HEADER_CREATION_GTPU_UDP_IPV6 OuterHeaderCreationMask = 1 << 1
	OUTER_HEADER_CREATION_UDP_IPV4      OuterHeaderCreationMask = 1 << 2
	OUTER_HEADER_CREATION_UDP_IPV6      OuterHeaderCreationMask = 1 << 3
	OUTER_HEADER_CREATION_IPV4          OuterHeaderCreationMask = 1 << 4
	OUTER_HEADER_CREATION_IPV6          OuterHeaderCreationMask = 1 << 5
)

type OuterHeaderCreation struct {
	Desc OuterHeaderCreationMask `yaml:"desc"`
	Teid uint32                  `yaml:"teid"`
	Ip   net.IP                  `yaml:"ip"`
	Port *uint16                 `yaml:"port,omitempty"`
}

func NewOuterGTPIPV4HeaderCreation(teid uint32, ip net.IP) *OuterHeaderCreation {
	r := &OuterHeaderCreation{Desc: OUTER_HEADER_CREATION_GTPU_UDP_IPV4, Ip: ip, Teid: teid}
	return r
}

func (ohc *OuterHeaderCreation) String() string {
	return fmt.Sprintf("%+v", *ohc)
}

func (ie *OuterHeaderCreation) Type() IEType {
	return OuterHeaderCreationIEType
}

func (ohc *OuterHeaderCreation) Marshal() []byte {
	b, n := newTLVBuffer(OuterHeaderCreationIEType, 0)
	b[n] = uint8(ohc.Desc)
	n += 2
	if ohc.Desc&(OUTER_HEADER_CREATION_GTPU_UDP_IPV4|OUTER_HEADER_CREATION_GTPU_UDP_IPV6) != 0 {
		binary.BigEndian.PutUint32(b[n:], ohc.Teid)
		n += 4
	}
	if ohc.Desc&(OUTER_HEADER_CREATION_GTPU_UDP_IPV4|OUTER_HEADER_CREATION_UDP_IPV4) != 0 {
		n += copy(b[n:], ohc.Ip.To4())
	}
	if ohc.Desc&(OUTER_HEADER_CREATION_GTPU_UDP_IPV6|OUTER_HEADER_CREATION_UDP_IPV6) != 0 {
		n += copy(b[n:], ohc.Ip.To16())
	}
	if ohc.Desc&(OUTER_HEADER_CREATION_UDP_IPV4|OUTER_HEADER_CREATION_UDP_IPV6) != 0 {
		binary.BigEndian.PutUint16(b[n:], *ohc.Port)
		n += 2
	}
	setTLVLength(b, n)
	return b[:n]
}

func (ohc *OuterHeaderCreation) UnMarshal(b []byte) {
	n := 0
	ohc.Desc = OuterHeaderCreationMask(b[n])
	n += 2
	if ohc.Desc&(OUTER_HEADER_CREATION_GTPU_UDP_IPV4|OUTER_HEADER_CREATION_GTPU_UDP_IPV6) != 0 {
		ohc.Teid = binary.BigEndian.Uint32(b[n:])
		n += 4
	}
	if ohc.Desc&(OUTER_HEADER_CREATION_GTPU_UDP_IPV4|OUTER_HEADER_CREATION_UDP_IPV4) != 0 {
		ohc.Ip = make([]byte, 4)
		copy(ohc.Ip, b[n:])
		n += 4
	}
	if ohc.Desc&(OUTER_HEADER_CREATION_GTPU_UDP_IPV6|OUTER_HEADER_CREATION_UDP_IPV6) != 0 {
		ohc.Ip = make([]byte, 16)
		copy(ohc.Ip, b[n:])
		n += 16
	}
	if ohc.Desc&(OUTER_HEADER_CREATION_UDP_IPV4|OUTER_HEADER_CREATION_UDP_IPV6) != 0 {
		port := binary.BigEndian.Uint16(b[n:])
		ohc.Port = &port
		n += 2
	}
}

// Forwarding Policy IE
type ForwardingPolicy string

func (fp *ForwardingPolicy) String() string {
	return fmt.Sprintf("%v", *fp)
}

func (ie *ForwardingPolicy) Type() IEType {
	return ForwardingPolicyIEType
}

func (fp *ForwardingPolicy) Marshal() []byte {
	s := string(*fp)
	b := make([]byte, 4+len(s)+1)
	binary.BigEndian.PutUint16(b, uint16(ForwardingPolicyIEType))
	binary.BigEndian.PutUint16(b[2:], uint16(1+len(s)))
	b[4] = byte(len(s))
	copy(b[5:], s)
	return b
}

func (fp *ForwardingPolicy) UnMarshal(b []byte) {
	len := b[0]
	*fp = ForwardingPolicy(b[1 : 1+len])
}

type ForwardingParameters struct {
	DestinationInterface DestinationInterface `yaml:"destinationInterface"`
	NetworkInstance      *NetworkInstance     `yaml:"networkInstance,omitempty"`
	RedirectInformation  *RedirectInformation `yaml:"redirectInformation,omitempty"`
	OuterHeaderCreation  *OuterHeaderCreation `yaml:"outerHeaderCreation,omitempty"`
	ForwardingPolicy     *ForwardingPolicy    `yaml:"forwardingPolicy,omitempty"`
}

func NewForwardingParameters(destInterface DestinationInterface) *ForwardingParameters {
	r := &ForwardingParameters{DestinationInterface: destInterface}
	return r
}

func (fp *ForwardingParameters) SetNetworkInstance(networkInstance string) {
	nwi := NetworkInstance(networkInstance)
	fp.NetworkInstance = &nwi
}

func (fp *ForwardingParameters) SetOuterHeaderCreation(ohc *OuterHeaderCreation) {
	fp.OuterHeaderCreation = ohc
}

func (fp *ForwardingParameters) String() string {
	return fmt.Sprintf("%+v", *fp)
}

func (ie *ForwardingParameters) Type() IEType {
	return ForwardingParametersIEType
}

func (fp *ForwardingParameters) Marshal() []byte {
	b, n := newTLVBuffer(ForwardingParametersIEType, 0)
	n += copy(b[n:], fp.DestinationInterface.Marshal())

	if fp.NetworkInstance != nil {
		n += copy(b[n:], fp.NetworkInstance.Marshal())
	}
	if fp.RedirectInformation != nil {
		n += copy(b[n:], fp.RedirectInformation.Marshal())
	}
	if fp.OuterHeaderCreation != nil {
		n += copy(b[n:], fp.OuterHeaderCreation.Marshal())
	}
	if fp.ForwardingPolicy != nil {
		n += copy(b[n:], fp.ForwardingPolicy.Marshal())
	}

	setTLVLength(b, n)
	return b[:n]
}

func (fp *ForwardingParameters) UnMarshal(b []byte) {
	n := 0
	inputLen := len(b)
	for {
		ieLen, ie, err := DecodePFCPInformationElement(b[n:])
		if err != nil {
			break //XX
		}
		if ie != nil {
			switch ie.(type) {
			case *DestinationInterface:
				fp.DestinationInterface = *ie.(*DestinationInterface)
			case *NetworkInstance:
				fp.NetworkInstance = ie.(*NetworkInstance)
			case *RedirectInformation:
				fp.RedirectInformation = ie.(*RedirectInformation)
			case *OuterHeaderCreation:
				fp.OuterHeaderCreation = ie.(*OuterHeaderCreation)
			case *ForwardingPolicy:
				fp.ForwardingPolicy = ie.(*ForwardingPolicy)
			}
		}
		n += ieLen
		if n >= inputLen {
			break
		}
	}
}

// Update Forwarding Parameters
type UpdateForwardingParameters struct {
	DestinationInterface *DestinationInterface `yaml:"destinationInterface,omitempty"`
	NetworkInstance      *NetworkInstance      `yaml:"networkInstance,omitempty"`
	RedirectInformation  *RedirectInformation  `yaml:"redirectInformation,omitempty"`
	OuterHeaderCreation  *OuterHeaderCreation  `yaml:"outerHeaderCreation,omitempty"`
	ForwardingPolicy     *ForwardingPolicy     `yaml:"forwardingPolicy,omitempty"`
}

func NewUpdateForwardingParameters() *UpdateForwardingParameters {
	r := &UpdateForwardingParameters{}
	return r
}

func (fp *UpdateForwardingParameters) SetDestinationInterface(dest DestinationInterface) {
	fp.DestinationInterface = &dest
}

func (fp *UpdateForwardingParameters) SetNetworkInstance(networkInstance string) {
	nwi := NetworkInstance(networkInstance)
	fp.NetworkInstance = &nwi
}

func (fp *UpdateForwardingParameters) SetOuterHeaderCreation(ohc *OuterHeaderCreation) {
	fp.OuterHeaderCreation = ohc
}

func (fp *UpdateForwardingParameters) String() string {
	return fmt.Sprintf("%+v", *fp)
}

func (ie *UpdateForwardingParameters) Type() IEType {
	return UpdateForwardingParametersIEType
}

func (fp *UpdateForwardingParameters) Marshal() []byte {
	b, n := newTLVBuffer(fp.Type(), 0)
	if fp.DestinationInterface != nil {
		n += copy(b[n:], fp.DestinationInterface.Marshal())
	}
	if fp.NetworkInstance != nil {
		n += copy(b[n:], fp.NetworkInstance.Marshal())
	}
	if fp.RedirectInformation != nil {
		n += copy(b[n:], fp.RedirectInformation.Marshal())
	}
	if fp.OuterHeaderCreation != nil {
		n += copy(b[n:], fp.OuterHeaderCreation.Marshal())
	}
	if fp.ForwardingPolicy != nil {
		n += copy(b[n:], fp.ForwardingPolicy.Marshal())
	}

	setTLVLength(b, n)
	return b[:n]
}

func (fp *UpdateForwardingParameters) UnMarshal(b []byte) {
	n := 0
	inputLen := len(b)
	for {
		ieLen, ie, err := DecodePFCPInformationElement(b[n:])
		if err != nil {
			break //XX
		}
		if ie != nil {
			switch ie.(type) {
			case *DestinationInterface:
				fp.DestinationInterface = ie.(*DestinationInterface)
			case *NetworkInstance:
				fp.NetworkInstance = ie.(*NetworkInstance)
			case *RedirectInformation:
				fp.RedirectInformation = ie.(*RedirectInformation)
			case *OuterHeaderCreation:
				fp.OuterHeaderCreation = ie.(*OuterHeaderCreation)
			case *ForwardingPolicy:
				fp.ForwardingPolicy = ie.(*ForwardingPolicy)
			}
		}
		n += ieLen
		if n >= inputLen {
			break
		}
	}
}

type UPFunctionFeatures struct {
	supportedFeatures           uint16
	additionalSupportedFeatures uint16
}

const (
	F_UPFF_BUCP  = 1 << iota
	F_UPFF_DDND  = 1 << iota
	F_UPFF_DLBD  = 1 << iota
	F_UPFF_TRST  = 1 << iota
	F_UPFF_FTUP  = 1 << iota
	F_UPFF_PFDM  = 1 << iota
	F_UPFF_HEEU  = 1 << iota
	F_UPFF_TREU  = 1 << iota
	F_UPFF_EMPU  = 1 << iota
	F_UPFF_PDIU  = 1 << iota
	F_UPFF_UDBC  = 1 << iota
	F_UPFF_QUOAC = 1 << iota
)

func NewUPFunctionFeatures(features uint16, additionalFeatures uint16) *UPFunctionFeatures {
	return &UPFunctionFeatures{supportedFeatures: features, additionalSupportedFeatures: additionalFeatures}
}

func (ie *UPFunctionFeatures) Type() IEType {
	return UPFunctionFeaturesIETYpe
}

func (features *UPFunctionFeatures) Marshal() []byte {
	b, n := newTLVBuffer(UPFunctionFeaturesIETYpe, 0)
	binary.BigEndian.PutUint16(b[n:], features.supportedFeatures)
	n += 2
	binary.BigEndian.PutUint16(b[n:], features.additionalSupportedFeatures)
	n += 2
	setTLVLength(b, n)
	return b[:n]
}

func (features *UPFunctionFeatures) UnMarshal(b []byte) {
	features.supportedFeatures = binary.BigEndian.Uint16(b)
	if len(b) > 2 {
		features.additionalSupportedFeatures = binary.BigEndian.Uint16(b[2:])
	}
}

func (features *UPFunctionFeatures) String() string {
	return fmt.Sprintf("UPFunctionFeatures[%x]", features.supportedFeatures)
}

func DecodePFCPInformationElement(b []byte) (n int, ie PFCPInformationElement, err error) {
	var tag IEType = IEType(binary.BigEndian.Uint16(b[n:]))
	n += 2
	len := binary.BigEndian.Uint16(b[n:])
	n += 2
	switch tag {
	case NodeIDIEType:
		ie = new(NodeID)
	case CauseIEType:
		ie = new(CauseIE)
	case UPFunctionFeaturesIETYpe:
		ie = new(UPFunctionFeatures)
	case FSEIDIETYPE:
		ie = new(FSEID)
	case CreatePDRIEType:
		ie = new(CreatePdr)
	case PDRIDIEType:
		ie = new(PdrID)
	case PrecedenceIEType:
		ie = new(Precedence)
	case FARIDIEType:
		ie = new(FarID)
	case OuterHeaderRemovelIEType:
		ie = new(OuterHeaderRemoval)
	case PDIIEType:
		ie = new(PDI)
	case FTEIDIEType:
		ie = new(FTEID)
	case SDFFilterIEType:
		ie = new(SDFFilter)
	case UEIPAddressIEType:
		ie = new(UEIPAddress)
	case NetworkInstanceIEType:
		ie = new(NetworkInstance)
	case SourceInterfaceIEType:
		ie = new(SourceInterface)
	case ApplicationIDIEType:
		ie = new(ApplicationID)
	case CreateFARIEType:
		ie = new(CreateFAR)
	case UpdateFARIEType:
		ie = new(UpdateFAR)
	case ApplyActionIEType:
		ie = new(ApplyAction)
	case ForwardingParametersIEType:
		ie = new(ForwardingParameters)
	case DestinationInterfaceIEType:
		ie = new(DestinationInterface)
	case RedirectInformationIEType:
		ie = new(RedirectInformation)
	case OuterHeaderCreationIEType:
		ie = new(OuterHeaderCreation)
	case ForwardingPolicyIEType:
		ie = new(ForwardingPolicy)
	case UpdateForwardingParametersIEType:
		ie = new(UpdateForwardingParameters)
	case RecoveryTimestampIEType:
		ie = new(RecoveryTimestamp)
	}
	if ie != nil {
		ie.UnMarshal(b[n : n+int(len)])
	}
	n += int(len)
	return n, ie, nil
}

const (
	HEADER_SEID = 1 << 0
	HEADER_MP   = 1 << 1
)

type PFCPMessageHeader struct {
	isSEIDSet            bool
	isMessagePrioritySet bool
	messageType          MessageType
	messageLength        uint16
	seid                 uint64
	sequenceNumber       uint32
	messagePriority      uint8
}

func (h *PFCPMessageHeader) String() string {
	s := "[type: " + h.messageType.String()
	if h.isSEIDSet {
		s += ",seid: " + strconv.FormatInt(int64(h.seid), 10)
	}
	return s + "]"
}

func (h *PFCPMessageHeader) SetSEID(seid uint64) {
	h.isSEIDSet = true
	h.seid = seid
}

func (h *PFCPMessageHeader) Marshal() ([]byte, error) {
	b := make([]byte, MaxSize)
	n := 0
	b[n] = (PFCP_VERSION << 5)
	if h.isSEIDSet {
		b[n] |= HEADER_SEID
	}
	if h.isMessagePrioritySet {
		b[n] |= HEADER_MP
	}
	n++
	b[n] = byte(h.messageType)
	n++
	binary.BigEndian.PutUint16(b[n:], h.messageLength)
	n += 2
	if h.isSEIDSet {
		binary.BigEndian.PutUint64(b[n:], h.seid)
		n += 8
	}
	b[n] = byte((h.sequenceNumber >> 16) & 0xFF)
	b[n+1] = byte((h.sequenceNumber >> 8) & 0xFF)
	b[n+2] = byte((h.sequenceNumber) & 0xFF)
	n += 3

	if h.isMessagePrioritySet {
		b[n] = h.messagePriority << 4
	}
	n++
	return b[:n], nil
}

func (h *PFCPMessageHeader) UnMarshal(b []byte) (n int, err error) {
	h.isSEIDSet = (b[n] & HEADER_SEID) != 0
	h.isMessagePrioritySet = (b[n] & HEADER_MP) != 0
	n++
	h.messageType = MessageType(b[n])
	n++
	h.messageLength = binary.BigEndian.Uint16(b[n:])
	n += 2
	if h.isSEIDSet {
		h.seid = binary.BigEndian.Uint64(b[n:])
		n += 8
	}
	h.sequenceNumber = (uint32(b[n]) << 16) | (uint32(b[n+1]) << 8) | uint32(b[n+2])
	n += 3
	if h.isMessagePrioritySet {
		h.messagePriority = b[n] >> 4
	}
	n++
	return n, err
}

type PFCPMessage struct {
	PFCPMessageHeader
	ies []PFCPInformationElement
}

func (m *PFCPMessage) String() string {
	s := "PFCP Message " + m.PFCPMessageHeader.String()
	if len(m.ies) > 0 {
		s = s + "\n"
	}
	for _, ie := range m.ies {
		s += "\t" + ie.String() + "\n"
	}
	return s
}

func (h *PFCPMessage) Marshal() ([]byte, error) {
	b, err := h.PFCPMessageHeader.Marshal()
	if err != nil {
		return nil, err
	}
	for _, ie := range h.ies {
		b = append(b, ie.Marshal()...)
	}
	// patch message length
	setTLVLength(b, len(b))
	return b, nil
}

func (h *PFCPMessage) UnMarshal(b []byte) (n int, err error) {
	n, err = h.PFCPMessageHeader.UnMarshal(b)
	if err != nil {
		return 0, err
	}
	var msgLen uint16 = h.messageLength - 3 - 1 // seqnum + spare
	if h.isSEIDSet {
		msgLen -= 8
	}
	var iesLen uint16 = 0
	for {
		if iesLen >= msgLen {
			break
		}
		ieLen, ie, err := DecodePFCPInformationElement(b[n:])
		if err != nil {
			return 0, err
		}
		if ie != nil {
			iesLen += uint16(ieLen)
			h.ies = append(h.ies, ie)
		} else {
			break
		}
		n += ieLen
	}
	return n, nil
}

func (m *PFCPMessage) getCause() Cause {
	for _, ie := range m.ies {
		if causeIE, ok := ie.(*CauseIE); ok {
			return causeIE.value
		}
	}
	return 0
}

func (m *PFCPMessage) FindIE(ieType IEType) PFCPInformationElement {
	for _, ie := range m.ies {
		if ie.Type() == ieType {
			return ie
		}
	}
	return nil
}

func (m *PFCPMessage) FindIEs(ieType IEType) []PFCPInformationElement {
	result := make([]PFCPInformationElement, 0)
	for _, ie := range m.ies {
		if ie.Type() == ieType {
			result = append(result, ie)
		}
	}
	return result
}

func newPFCPSessionDeleteRequestMessage(fseid *FSEID) (msg *PFCPMessage) {
	msg = new(PFCPMessage)
	msg.messageType = SessionEtablismentRequest
	msg.SetSEID(fseid.seid)
	return msg
}

type MsgHandler func(msg *PFCPMessage)
type PFCPConnection struct {
	laddr, raddr    *net.UDPAddr
	localAddress    string
	conn            *net.UDPConn
	sequenceNumber  uint32
	startTime       time.Time
	nodeID          *NodeID
	outMessages     chan *Request
	pendingRequests map[uint32]*Request
	msgHandler      PFCPMessageHandler
	done            chan struct{}
}

type Request struct {
	msg   *PFCPMessage
	reply chan Cause
}

func newRequest(msg *PFCPMessage) *Request {
	return &Request{msg: msg, reply: make(chan Cause, 1)}
}

func (r *Request) GetResponse() (Cause, bool) {
	select {
	case c := <-r.reply:
		return c, false
	case <-time.After(5 * time.Second):
		return 0, true
	}
}

func NewPFCPListener(localAddr string) (*PFCPConnection, error) {
	laddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, err
	}
	idx := strings.IndexByte(localAddr, ':')
	if idx == -1 {
		idx = len(localAddr)
	}
	nodeID := NewNodeID(localAddr[:idx])
	ep := PFCPConnection{laddr: laddr, localAddress: string(localAddr[:idx]), nodeID: nodeID,
		outMessages: make(chan *Request), pendingRequests: make(map[uint32]*Request), done: make(chan struct{})}
	ep.conn, err = net.ListenUDP("udp4", ep.laddr)
	if err != nil {
		return nil, err
	}
	if err := ep.Start(); err != nil {
		return nil, err
	}
	return &ep, nil
}

func NewPCPFConnection(localAddr, remoteAddr string) (*PFCPConnection, error) {
	raddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return nil, err
	}
	laddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, err
	}
	idx := strings.IndexByte(localAddr, ':')
	if idx == -1 {
		idx = len(localAddr)
	}
	nodeID := NewNodeID(localAddr[:idx])
	ep := PFCPConnection{raddr: raddr, laddr: laddr, localAddress: string(localAddr[:idx]), nodeID: nodeID,
		outMessages: make(chan *Request), pendingRequests: make(map[uint32]*Request), done: make(chan struct{})}
	ep.startTime = time.Now()
	ep.conn, err = net.DialUDP("udp", ep.laddr, ep.raddr)
	if err != nil {
		return nil, err
	}
	if err := ep.Start(); err != nil {
		return nil, err
	}
	return &ep, nil
}

func (ep *PFCPConnection) NodeID() *NodeID {
	return ep.nodeID
}

func (ep *PFCPConnection) StartTime() time.Time {
	return ep.startTime
}

func (ep *PFCPConnection) SetMessageHandler(msgHandler PFCPMessageHandler) {
	ep.msgHandler = msgHandler
}

type PFCPMessageHandler interface {
	HandleAssociationSetupRequest(endpoint *PFCPConnection, msg *PFCPMessage)
	HandleSessionEstablishmentRequest(endpoint *PFCPConnection, msg *PFCPMessage)
	HandleSessionModificationRequest(endpoint *PFCPConnection, msg *PFCPMessage)
	HandleSessionDeletionRequest(endpoint *PFCPConnection, msg *PFCPMessage)
}

func (ep *PFCPConnection) Start() error {
	buffer := make([]byte, 1024)
	inMessages := make(chan *PFCPMessage)
	go func() {
	loop:
		for {
			select {
			case <-ep.done:
				break loop
			default:
			}
			if err := ep.conn.SetDeadline(
				time.Now().Add(2 * time.Second)); err != nil {
				fmt.Printf("Failed to det deadline %v\n", err)
			}
			n, raddr, err := ep.conn.ReadFromUDP(buffer)
			if err != nil {
				if nerr, ok := err.(net.Error); !ok || !nerr.Timeout() {
					fmt.Println(err)
				}
				continue
			}
			ep.raddr = raddr
			//fmt.Printf("Received %d bytes from %v\n", n, raddr)
			msg := new(PFCPMessage)
			if _, err := msg.UnMarshal(buffer[:n]); err != nil {
				fmt.Printf("Failed to unmarshall PFCP message %v\n", err)
				continue
			}
			inMessages <- msg
		}

	}()

	go func() {
		for {
			select {
			case req := <-ep.outMessages:
				req.msg.sequenceNumber = ep.sequenceNumber
				b, err := req.msg.Marshal()
				if err != nil {
					continue //XX
				}
				ep.pendingRequests[ep.sequenceNumber] = req
				if ep.conn.RemoteAddr() == nil {
					_, err = ep.conn.WriteToUDP(b, ep.raddr)
				} else {
					_, err = ep.conn.Write(b)
				}
				if err != nil {
					fmt.Printf("Failed to send UDP message %v\n", err)
					delete(ep.pendingRequests, ep.sequenceNumber)
					continue
				}
				ep.sequenceNumber++
			case msg := <-inMessages:
				// fmt.Printf("Received %s\n", msg)
				switch msg.messageType {
				case HeartbeatRequest:
					response := new(PFCPMessage)
					response.messageType = HeartbeatResponse
					response.sequenceNumber = msg.sequenceNumber
					response.ies = append(response.ies, NewRecoveryTimestamp(ep.startTime))
					if err := ep.sendResponse(response); err != nil {
						fmt.Printf("Failed to send response %s\n", err)
					}
				case HeartbeatResponse, AssociationSetupResponse, SessionEtablismentResponse, SessionModificationResponse, SessionDeletionResponse:
					req := ep.pendingRequests[msg.sequenceNumber]
					if req == nil {
						fmt.Printf("Receive PFCP response message for unknown request, sequence number=%d\n", msg.sequenceNumber)
						continue
					}
					req.reply <- msg.getCause()
					delete(ep.pendingRequests, msg.sequenceNumber)
				case AssociationSetupRequest:
					if ep.msgHandler != nil {
						ep.msgHandler.HandleAssociationSetupRequest(ep, msg)
					} else {
						fmt.Printf("Ignoring PFCP message with type %d\n", msg.messageType)
					}
				case SessionEtablismentRequest:
					if ep.msgHandler != nil {
						ep.msgHandler.HandleSessionEstablishmentRequest(ep, msg)
					} else {
						fmt.Printf("Ignoring PFCP message with type %d\n", msg.messageType)
					}
				case SessionModificationRequest:
					if ep.msgHandler != nil {
						ep.msgHandler.HandleSessionModificationRequest(ep, msg)
					} else {
						fmt.Printf("Ignoring PFCP message with type %d\n", msg.messageType)
					}
				case SessionDeletionRequest:
					if ep.msgHandler != nil {
						ep.msgHandler.HandleSessionDeletionRequest(ep, msg)
					} else {
						fmt.Printf("Ignoring PFCP message with type %d\n", msg.messageType)
					}
				default:
					fmt.Printf("Ignoring PFCP message with type %d\n", msg.messageType)
				}
			case <-ep.done:
				break
			}
		}

	}()
	return nil
}

func (ep *PFCPConnection) Close() {
	close(ep.done)
	ep.conn.Close() //XX
}

func (ep *PFCPConnection) sendRequest(msg *PFCPMessage) (*Request, error) {
	req := newRequest(msg)
	ep.outMessages <- req
	return req, nil
}

func (ep *PFCPConnection) SendSetupAssociationRequest() (*Request, error) {
	msg := new(PFCPMessage)
	msg.messageType = AssociationSetupRequest
	msg.ies = append(msg.ies, ep.nodeID, NewRecoveryTimestamp(ep.startTime))
	return ep.sendRequest(msg)
}

func (ep *PFCPConnection) SendResponse(req *PFCPMessage, msgType MessageType, elements []PFCPInformationElement) error {
	resp := new(PFCPMessage)
	resp.messageType = msgType
	resp.sequenceNumber = req.sequenceNumber
	if req.isSEIDSet {
		resp.SetSEID(req.seid)
	}
	resp.ies = elements
	return ep.sendResponse(resp)
}

func (ep *PFCPConnection) SendSessionEstablishmentRequest(params *SessionEstablishmentParams) (*Request, error) {
	msg := new(PFCPMessage)
	msg.messageType = SessionEtablismentRequest
	msg.SetSEID(params.Seid)
	msg.ies = append(msg.ies, ep.nodeID)
	msg.ies = append(msg.ies, NewFSEID(ep.localAddress, params.Seid))
	for _, pdr := range params.Pdrs {
		msg.ies = append(msg.ies, pdr)
	}
	for _, far := range params.Fars {
		msg.ies = append(msg.ies, far)
	}
	return ep.sendRequest(msg)
}

func (ep *PFCPConnection) SendSessionModificationRequest(params *SessionModificationParams) (*Request, error) {
	msg := new(PFCPMessage)
	msg.messageType = SessionModificationRequest
	msg.SetSEID(params.Seid)
	for _, uf := range params.UpdateFars {
		msg.ies = append(msg.ies, uf)
	}
	return ep.sendRequest(msg)
}

func (ep *PFCPConnection) SendSessionDeletionRequest(params *SessionDeletionParams) (*Request, error) {
	msg := new(PFCPMessage)
	msg.messageType = SessionDeletionRequest
	msg.SetSEID(params.Seid)
	return ep.sendRequest(msg)
}

func (ep *PFCPConnection) SendHeartbeatRequest() (*Request, error) {
	hb := new(PFCPMessage)
	hb.messageType = HeartbeatRequest
	hb.ies = append(hb.ies, NewRecoveryTimestamp(ep.startTime))
	return ep.sendRequest(hb)
}

func (ep *PFCPConnection) sendResponse(msg *PFCPMessage) error {
	b, err := msg.Marshal()
	if err != nil {
		return err
	}
	if ep.conn.RemoteAddr() == nil {
		_, err = ep.conn.WriteToUDP(b, ep.raddr)
	} else {
		_, err = ep.conn.Write(b)
	}
	if err != nil {
		return err
	}
	return nil
}

type SessionEstablishmentParams struct {
	Seid uint64       `yaml:"seid"`
	Pdrs []*CreatePdr `yaml:"pdrs"`
	Fars []*CreateFAR `yaml:"fars"`
}

type SessionEstablishmentMessage struct {
	MessageType   string                      `yaml:"messageType"`
	MessageParams *SessionEstablishmentParams `yaml:"messageParams"`
}

type SessionModificationParams struct {
	Seid       uint64       `yaml:"seid"`
	UpdateFars []*UpdateFAR `yaml:"updateFars"`
}

type SessionModificationMessage struct {
	MessageType   string                     `yaml:"messageType"`
	MessageParams *SessionModificationParams `yaml:"messageParams"`
}

type SessionDeletionParams struct {
	Seid uint64 `yaml:"seid"`
}

type SessionDeletionMessage struct {
	MessageType   string                 `yaml:"messageType"`
	MessageParams *SessionDeletionParams `yaml:"messageParams"`
}

type SessionMessage struct {
	MessageType   string      `yaml:"messageType"`
	MessageParams interface{} `yaml:"messageParams"`
}

func (sm *SessionMessage) UnmarshalYAML(unmarshal func(interface{}) error) error {
	t := new(struct {
		MessageType string `yaml:"messageType"`
	})
	if err := unmarshal(t); err != nil {
		return err
	}
	switch t.MessageType {
	case "SessionEstablishmentRequest":
		m := new(SessionEstablishmentMessage)
		if err := unmarshal(m); err != nil {
			return err
		}
		sm.MessageParams = m.MessageParams
	case "SessionModificationRequest":
		m := new(SessionModificationMessage)
		if err := unmarshal(m); err != nil {
			return err
		}
		sm.MessageParams = m.MessageParams
	case "SessionDeletionRequest":
		m := new(SessionDeletionMessage)
		if err := unmarshal(m); err != nil {
			return err
		}
		sm.MessageParams = m.MessageParams
	default:
		return fmt.Errorf("unknown message type %s", sm.MessageType)
	}

	return nil
}

type SessionMessages struct {
	Messages []*SessionMessage `yaml:"messages"`
}
