/* Copyright (c) 2011-2014 ETH Zürich. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the names of ETH Zürich nor the names of other contributors 
 *      may be used to endorse or promote products derived from this software 
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL ETH 
 * ZURICH BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY 
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

 
#include <cassert>
#include <climits>
#include <sstream>
#include <string>

#include "InfoElement.h"
#include "InfoModel.h"
#include "Constants.h"

#include "exceptions/IESpecError.h"

namespace libfc {

  InfoModel& InfoModel::instance() {
    static InfoModel instance_;
    return instance_;
  }

  const IEType* InfoModel::lookupIEType(const std::string &name) const {
    std::lock_guard<std::recursive_mutex> locker(lock);

    std::map<std::string, const IEType*>::const_iterator iter;
    
    if ((iter = ietypes_byname_.find(name)) == ietypes_byname_.end()) {
      return NULL;
    } else { 
      return iter->second;
    }
  }

  const IEType* InfoModel::lookupIEType(const unsigned int number) const { 
    std::lock_guard<std::recursive_mutex> locker(lock);

    return ietypes_bynum_.at(number); 
  }

  InfoModel::InfoModel() {
    initTypes();
  }

  static void parseIESpec_NumPen(std::istringstream& iestream, 
                                 unsigned int& number,
                                 unsigned int& pen) {
    // get the first number
    iestream >> number;
    if (iestream.fail())
      throw IESpecError("badly formatted IE number / PEN");
    
    // see how we're terminated
    char c = iestream.get();
    if (c == '/') {
      // first number was a pen. get the next.
      pen = number;
      iestream >> number;
      if (iestream.fail())
        throw IESpecError("badly formatted IE number");
    } else {
      pen = 0;
      iestream.unget();
    }
  }

  static void parseIESpec_Length(std::istringstream& iestream,
                                 unsigned int& len) {
    std::stringbuf lenbuf;
    
    iestream.get(lenbuf, ']');
    
    if (lenbuf.str()[0] == 'v') {
      len = kIpfixVarlen;
    } else {  // parse size
      unsigned long ullen;
      try {
        ullen = std::stoul(lenbuf.str());
      } catch (std::invalid_argument) {
        throw IESpecError("bad size " + lenbuf.str() + " (invalid format)");
      } catch (std::out_of_range) {
        throw IESpecError("bad size " + lenbuf.str() + " (out of range)");
      }

      if (ullen != kIpfixVarlen &&
          ullen > kIpfixVarlen - kIpfixMessageHeaderLen - kIpfixSetHeaderLen) {
          throw IESpecError("bad size " + std::to_string(ullen)
                            + " (too large)");
      }
      
      len = static_cast<unsigned int>(ullen);
    }
  }

  static void match(std::istringstream& iestream, char x) {
    char c = iestream.get();
    if (iestream.fail()) {
      std::ostringstream b;
      b << "expected character '" << x << "', but read failed";
      throw IESpecError(b.str());
    } else if (c != x) {
      std::ostringstream b;
      b << "expected character '" << x << "', but got '" << c << "'";
      throw IESpecError(b.str());
    }
  }
    
  static void parseIESpec_Initial(std::istringstream& iestream, 
                                  std::stringbuf& namebuf, bool& name_set,
                                  std::stringbuf& typebuf, bool& type_set,
                                  std::stringbuf& ctxbuf,  bool& ctx_set,
                                  unsigned int& number,    bool& number_set,
                                  unsigned int& pen,       bool& pen_set,
                                  unsigned int& len,       bool& len_set) {
    char c = iestream.get();
    if (iestream.eof()) return;
    
    switch (c) {
    case '(':
      assert(!pen_set || number_set);
      if (number_set)
        throw IESpecError("IESpec contains number / pen more than once");
              
      parseIESpec_NumPen(iestream, number, pen);
      match(iestream, ')');
      number_set = true;
      pen_set = pen != 0;
      break;
    case '[':
      if (len_set)
        throw IESpecError("IESpec contains length more than once");
      parseIESpec_Length(iestream, len);
      match(iestream, ']');
      len_set = true;
      break;
    case '<':
      if (type_set)
        throw IESpecError("IESpec contains type more than once");
      iestream.get(typebuf, '>');
      match(iestream, '>');
      type_set = true;
      break;
    case '{':
      if (ctx_set)
        throw IESpecError("IESpec contains contextf more than once");
      iestream.get(ctxbuf, '}');
      match(iestream, '}');
      ctx_set = true;
      break;
    default:
      if (name_set)
        throw IESpecError("IESpec contains name more than once");
      do {
        namebuf.sputc(c);
        c = iestream.get();
      } while (!iestream.eof() 
               && c != '(' && c != '{' && c != '<' && c != '[');
      if (!iestream.eof())
        iestream.unget();
      name_set = true;
      break;
    }
  }

  const InfoElement InfoModel::parseIESpec(const std::string& iespec) const {
    std::lock_guard<std::recursive_mutex> locker(lock);
    
    // check for name-only IE
    // WORKAROUND for broken libc++ on Mac OS X Lion
    if ((iespec.find('(') == std::string::npos) &&
        (iespec.find('[') == std::string::npos) &&
        (iespec.find('<') == std::string::npos) &&
        (iespec.find('{') == std::string::npos))
      {
        InfoElement ie(iespec, 0, 0, 0, 0);
        return ie;
      }
    
    std::istringstream iestream(iespec);
    std::stringbuf namebuf, typebuf, ctxbuf;
    unsigned int number = 0, pen = 0, len = 0;
    bool name_set = false;
    bool type_set = false;
    bool ctx_set = false;
    bool number_set = false;
    bool pen_set = false;
    bool len_set = false;
    
    while (!iestream.eof()) {
      parseIESpec_Initial(iestream, 
                          namebuf, name_set,
                          typebuf, type_set,
                          ctxbuf, ctx_set,
                          number, number_set,
                          pen, pen_set,
                          len, len_set);
    }
    
    const IEType *ietype = lookupIEType(typebuf.str());
    InfoElement ie(namebuf.str(), pen, number, ietype, len);
    return ie;
  }

  const InfoElement* InfoModel::add(const InfoElement& ie) {
    std::lock_guard<std::recursive_mutex> locker(lock);

    // Short circuit unless we have a record valid for insertion:
    // at least a name, number, and valid, known type
    if (!ie.name().size() || !ie.number() || ie.ietype() == IEType::unknown()) {
      throw IESpecError("incomplete IESpec for InfoModel addition");
    }
  
    const InfoElement* ret = 0;

    // Only add if we don't have an existing IE for the given name and pen
    if ((ret = lookupIE(ie.pen(), ie.number(), ie.len())) != 0) return ret;


    if (ie.pen()) {
      name_registry_[ie.name()] = 
        pen_registry_[ie.pen()][ie.number()] = 
        std::shared_ptr<InfoElement>(new InfoElement(ie));
      // std::cerr << "add  PEN IE " << ie.pen() << "/" << ie.number() << " " << ie.name() << std::endl;
    } else {
      name_registry_[ie.name()] = 
        iana_registry_[ie.number()] = 
        std::shared_ptr<InfoElement>(new InfoElement(ie));
      // std::cerr << "add IANA IE " << ie.number() << " " << ie.name() << std::endl;
    }

    return name_registry_[ie.name()].get();
  }

  void InfoModel::add(const std::string& iespec) {
    std::lock_guard<std::recursive_mutex> locker(lock);

    add(parseIESpec(iespec));
  }

  const InfoElement* InfoModel::add_unknown(uint32_t pen, uint16_t number, uint16_t len) {
    std::lock_guard<std::recursive_mutex> locker(lock);

    /* Naming convention from Brian's Python code. */
    std::string name = "__ipfix_";

    InfoElement ie(name, pen, number, lookupIEType("octetArray"), len);

    return add(ie);
  }
  
  const InfoElement* InfoModel::lookupIE(uint32_t pen, uint16_t number, uint16_t len) const {  
    std::lock_guard<std::recursive_mutex> locker(lock);

    std::map<uint16_t, std::shared_ptr<InfoElement> >::const_iterator iter;

    //std::cerr << "lookupIE (" << pen << "/" << number << ")[" << len << "]" << std::endl;
    if (pen) {
      std::map<uint32_t, std::map<uint16_t, std::shared_ptr<InfoElement> > >::const_iterator peniter;

      if ((peniter = pen_registry_.find(pen)) == pen_registry_.end()) {
        //std::cerr << "    no such pen" << std::endl;
        return NULL;
      } else {
        if ((iter = peniter->second.find(number)) == peniter->second.end()) {
          //std::cerr << "    not in pen registry" << std::endl;
          return NULL;
        }
      }
    } else {
      if ((iter = iana_registry_.find(number)) == iana_registry_.end()) {
        //std::cerr << "    not in iana registry" << std::endl;
        return NULL;
      }
    }
    
    return iter->second->forLen(len);
  }

  const InfoElement *InfoModel::lookupIE(const InfoElement& specie) const {
    std::lock_guard<std::recursive_mutex> locker(lock);

    if (specie.number()) {
      return lookupIE(specie.pen(), specie.number(), specie.len());
    } else if (specie.name().empty()) {
      // Nothing to look up.
      throw IESpecError("incomplete IESpec for InfoModel lookup.");
    } else {
      // std::cerr << "lookupIE " << specie.name() << std::endl;
      std::map<std::string, std::shared_ptr<InfoElement> >::const_iterator iter = name_registry_.find(specie.name());
      if (iter == name_registry_.end()) {
        // std::cerr << "    not in name registry" << std::endl;
        return NULL;
      } else {
        return iter->second->forLen(specie.len());
      }
    }
  }

  const InfoElement *InfoModel::lookupIE(const std::string& iespec) const {
    std::lock_guard<std::recursive_mutex> locker(lock);

    // Parse the Information Element and look it up
    // std::cerr << "lookup " << iespec << " by std::string" << std::endl;
    return lookupIE(parseIESpec(iespec));
  }    

  void InfoModel::dump(std::ostream &os) const {
    std::lock_guard<std::recursive_mutex> locker(lock);

    std::map<uint16_t, std::shared_ptr<InfoElement> >::const_iterator   iana_keyiter;

    for (iana_keyiter = iana_registry_.begin();
         iana_keyiter != iana_registry_.end();
         iana_keyiter++) {
      os << iana_keyiter->second->toIESpec() << std::endl;
    }
  }

  void InfoModel::registerIEType(const IEType *iet) {
    std::lock_guard<std::recursive_mutex> locker(lock);

    ietypes_bynum_[iet->number()] = iet;
    ietypes_byname_[iet->name()] = iet;
  }

  void InfoModel::initTypes() {
    std::lock_guard<std::recursive_mutex> locker(lock);

    ietypes_bynum_.resize(IEType::ieTypeCount());
    registerIEType(IEType::octetArray());
    registerIEType(IEType::unsigned8());
    registerIEType(IEType::unsigned16());
    registerIEType(IEType::unsigned32());
    registerIEType(IEType::unsigned64());
    registerIEType(IEType::signed8());
    registerIEType(IEType::signed16());
    registerIEType(IEType::signed32());
    registerIEType(IEType::signed64());
    registerIEType(IEType::float32());
    registerIEType(IEType::float64());
    registerIEType(IEType::boolean());
    registerIEType(IEType::macAddress());
    registerIEType(IEType::string());
    registerIEType(IEType::dateTimeSeconds());
    registerIEType(IEType::dateTimeMilliseconds());
    registerIEType(IEType::dateTimeMicroseconds());
    registerIEType(IEType::dateTimeNanoseconds()); 
    registerIEType(IEType::ipv4Address());
    registerIEType(IEType::ipv6Address());
  }


  void InfoModel::defaultIPFIX() {
    std::lock_guard<std::recursive_mutex> locker(lock);

		const std::string items[] = {
			"octetDeltaCount(1)<unsigned64>[8]",
			"packetDeltaCount(2)<unsigned64>[8]",
			"deltaFlowCount(3)<unsigned64>[8]",
			"protocolIdentifier(4)<unsigned8>[1]",
			"ipClassOfService(5)<unsigned8>[1]",
			"tcpControlBits(6)<unsigned16>[2]",
			"sourceTransportPort(7)<unsigned16>[2]",
			"sourceIPv4Address(8)<ipv4Address>[4]",
			"sourceIPv4PrefixLength(9)<unsigned8>[1]",
			"ingressInterface(10)<unsigned32>[4]",
			"destinationTransportPort(11)<unsigned16>[2]",
			"destinationIPv4Address(12)<ipv4Address>[4]",
			"destinationIPv4PrefixLength(13)<unsigned8>[1]",
			"egressInterface(14)<unsigned32>[4]",
			"ipNextHopIPv4Address(15)<ipv4Address>[4]",
			"bgpSourceAsNumber(16)<unsigned32>[4]",
			"bgpDestinationAsNumber(17)<unsigned32>[4]",
			"bgpNextHopIPv4Address(18)<ipv4Address>[4]",
			"postMCastPacketDeltaCount(19)<unsigned64>[8]",
			"postMCastOctetDeltaCount(20)<unsigned64>[8]",
			"flowEndSysUpTime(21)<unsigned32>[4]",
			"flowStartSysUpTime(22)<unsigned32>[4]",
			"postOctetDeltaCount(23)<unsigned64>[8]",
			"postPacketDeltaCount(24)<unsigned64>[8]",
			"minimumIpTotalLength(25)<unsigned64>[8]",
			"maximumIpTotalLength(26)<unsigned64>[8]",
			"sourceIPv6Address(27)<ipv6Address>[16]",
			"destinationIPv6Address(28)<ipv6Address>[16]",
			"sourceIPv6PrefixLength(29)<unsigned8>[1]",
			"destinationIPv6PrefixLength(30)<unsigned8>[1]",
			"flowLabelIPv6(31)<unsigned32>[4]",
			"icmpTypeCodeIPv4(32)<unsigned16>[2]",
			"igmpType(33)<unsigned8>[1]",
			"flowActiveTimeout(36)<unsigned16>[2]",
			"flowIdleTimeout(37)<unsigned16>[2]",
			"exportedOctetTotalCount(40)<unsigned64>[8]",
			"exportedMessageTotalCount(41)<unsigned64>[8]",
			"exportedFlowRecordTotalCount(42)<unsigned64>[8]",
			"sourceIPv4Prefix(44)<ipv4Address>[4]",
			"destinationIPv4Prefix(45)<ipv4Address>[4]",
			"mplsTopLabelType(46)<unsigned8>[1]",
			"mplsTopLabelIPv4Address(47)<ipv4Address>[4]",
			"samplerId(48)<unsigned8>",
			"classId(51)<unsigned8>",
			"minimumTTL(52)<unsigned8>[1]",
			"maximumTTL(53)<unsigned8>[1]",
			"fragmentIdentification(54)<unsigned32>[4]",
			"postIpClassOfService(55)<unsigned8>[1]",
			"sourceMacAddress(56)<macAddress>[6]",
			"postDestinationMacAddress(57)<macAddress>[6]",
			"vlanId(58)<unsigned16>[2]",
			"postVlanId(59)<unsigned16>[2]",
			"ipVersion(60)<unsigned8>[1]",
			"flowDirection(61)<unsigned8>[1]",
			"ipNextHopIPv6Address(62)<ipv6Address>[16]",
			"bgpNextHopIPv6Address(63)<ipv6Address>[16]",
			"ipv6ExtensionHeaders(64)<unsigned32>[4]",
			"mplsTopLabelStackSection(70)<octetArray>[65535]",
			"mplsLabelStackSection2(71)<octetArray>[65535]",
			"mplsLabelStackSection3(72)<octetArray>[65535]",
			"mplsLabelStackSection4(73)<octetArray>[65535]",
			"mplsLabelStackSection5(74)<octetArray>[65535]",
			"mplsLabelStackSection6(75)<octetArray>[65535]",
			"mplsLabelStackSection7(76)<octetArray>[65535]",
			"mplsLabelStackSection8(77)<octetArray>[65535]",
			"mplsLabelStackSection9(78)<octetArray>[65535]",
			"mplsLabelStackSection10(79)<octetArray>[65535]",
			"destinationMacAddress(80)<macAddress>[6]",
			"postSourceMacAddress(81)<macAddress>[6]",
			"interfaceName(82)<string>[65535]",
			"interfaceDescription(83)<string>[65535]",
			"octetTotalCount(85)<unsigned64>[8]",
			"packetTotalCount(86)<unsigned64>[8]",
			"fragmentOffset(88)<unsigned16>[2]",
			"mplsVpnRouteDistinguisher(90)<octetArray>[65535]",
			"mplsTopLabelPrefixLength(91)<unsigned8>[1]",
			"applicationDescription(94)<string>[65535]",
			"applicationId(95)<octetArray>[65535]",
			"applicationName(96)<string>[65535]",
			"postIpDiffServCodePoint(98)<unsigned8>[1]",
			"multicastReplicationFactor(99)<unsigned32>[4]",
			"classificationEngineId(101)<unsigned8>[1]",
			"bgpNextAdjacentAsNumber(128)<unsigned32>[4]",
			"bgpPrevAdjacentAsNumber(129)<unsigned32>[4]",
			"exporterIPv4Address(130)<ipv4Address>[4]",
			"exporterIPv6Address(131)<ipv6Address>[16]",
			"droppedOctetDeltaCount(132)<unsigned64>[8]",
			"droppedPacketDeltaCount(133)<unsigned64>[8]",
			"droppedOctetTotalCount(134)<unsigned64>[8]",
			"droppedPacketTotalCount(135)<unsigned64>[8]",
			"flowEndReason(136)<unsigned8>[1]",
			"commonPropertiesId(137)<unsigned64>[8]",
			"observationPointId(138)<unsigned64>[8]",
			"icmpTypeCodeIPv6(139)<unsigned16>[2]",
			"mplsTopLabelIPv6Address(140)<ipv6Address>[16]",
			"lineCardId(141)<unsigned32>[4]",
			"portId(142)<unsigned32>[4]",
			"meteringProcessId(143)<unsigned32>[4]",
			"exportingProcessId(144)<unsigned32>[4]",
			"templateId(145)<unsigned16>[2]",
			"wlanChannelId(146)<unsigned8>[1]",
			"wlanSSID(147)<string>[65535]",
			"flowId(148)<unsigned64>[8]",
			"observationDomainId(149)<unsigned32>[4]",
			"flowStartSeconds(150)<dateTimeSeconds>[4]",
			"flowEndSeconds(151)<dateTimeSeconds>[4]",
			"flowStartMilliseconds(152)<dateTimeMilliseconds>[8]",
			"flowEndMilliseconds(153)<dateTimeMilliseconds>[8]",
			"flowStartMicroseconds(154)<dateTimeMicroseconds>",
			"flowEndMicroseconds(155)<dateTimeMicroseconds>",
			"flowStartNanoseconds(156)<dateTimeNanoseconds>",
			"flowEndNanoseconds(157)<dateTimeNanoseconds>",
			"flowStartDeltaMicroseconds(158)<unsigned32>[4]",
			"flowEndDeltaMicroseconds(159)<unsigned32>[4]",
			"systemInitTimeMilliseconds(160)<dateTimeMilliseconds>[8]",
			"flowDurationMilliseconds(161)<unsigned32>[4]",
			"flowDurationMicroseconds(162)<unsigned32>[4]",
			"observedFlowTotalCount(163)<unsigned64>[8]",
			"ignoredPacketTotalCount(164)<unsigned64>[8]",
			"ignoredOctetTotalCount(165)<unsigned64>[8]",
			"notSentFlowTotalCount(166)<unsigned64>[8]",
			"notSentPacketTotalCount(167)<unsigned64>[8]",
			"notSentOctetTotalCount(168)<unsigned64>[8]",
			"destinationIPv6Prefix(169)<ipv6Address>[16]",
			"sourceIPv6Prefix(170)<ipv6Address>[16]",
			"postOctetTotalCount(171)<unsigned64>[8]",
			"postPacketTotalCount(172)<unsigned64>[8]",
			"flowKeyIndicator(173)<unsigned64>[8]",
			"postMCastPacketTotalCount(174)<unsigned64>[8]",
			"postMCastOctetTotalCount(175)<unsigned64>[8]",
			"icmpTypeIPv4(176)<unsigned8>[1]",
			"icmpCodeIPv4(177)<unsigned8>[1]",
			"icmpTypeIPv6(178)<unsigned8>[1]",
			"icmpCodeIPv6(179)<unsigned8>[1]",
			"udpSourcePort(180)<unsigned16>[2]",
			"udpDestinationPort(181)<unsigned16>[2]",
			"tcpSourcePort(182)<unsigned16>[2]",
			"tcpDestinationPort(183)<unsigned16>[2]",
			"tcpSequenceNumber(184)<unsigned32>[4]",
			"tcpAcknowledgementNumber(185)<unsigned32>[4]",
			"tcpWindowSize(186)<unsigned16>[2]",
			"tcpUrgentPointer(187)<unsigned16>[2]",
			"tcpHeaderLength(188)<unsigned8>[1]",
			"ipHeaderLength(189)<unsigned8>[1]",
			"totalLengthIPv4(190)<unsigned16>[2]",
			"payloadLengthIPv6(191)<unsigned16>[2]",
			"ipTTL(192)<unsigned8>[1]",
			"nextHeaderIPv6(193)<unsigned8>[1]",
			"mplsPayloadLength(194)<unsigned32>[4]",
			"ipDiffServCodePoint(195)<unsigned8>[1]",
			"ipPrecedence(196)<unsigned8>[1]",
			"fragmentFlags(197)<unsigned8>[1]",
			"octetDeltaSumOfSquares(198)<unsigned64>[8]",
			"octetTotalSumOfSquares(199)<unsigned64>[8]",
			"mplsTopLabelTTL(200)<unsigned8>[1]",
			"mplsLabelStackLength(201)<unsigned32>[4]",
			"mplsLabelStackDepth(202)<unsigned32>[4]",
			"mplsTopLabelExp(203)<unsigned8>[1]",
			"ipPayloadLength(204)<unsigned32>[4]",
			"udpMessageLength(205)<unsigned16>[2]",
			"isMulticast(206)<unsigned8>[1]",
			"ipv4IHL(207)<unsigned8>[1]",
			"ipv4Options(208)<unsigned32>[4]",
			"tcpOptions(209)<unsigned64>[8]",
			"paddingOctets(210)<octetArray>[65535]",
			"collectorIPv4Address(211)<ipv4Address>[4]",
			"collectorIPv6Address(212)<ipv6Address>[16]",
			"exportInterface(213)<unsigned32>[4]",
			"exportProtocolVersion(214)<unsigned8>[1]",
			"exportTransportProtocol(215)<unsigned8>[1]",
			"collectorTransportPort(216)<unsigned16>[2]",
			"exporterTransportPort(217)<unsigned16>[2]",
			"tcpSynTotalCount(218)<unsigned64>[8]",
			"tcpFinTotalCount(219)<unsigned64>[8]",
			"tcpRstTotalCount(220)<unsigned64>[8]",
			"tcpPshTotalCount(221)<unsigned64>[8]",
			"tcpAckTotalCount(222)<unsigned64>[8]",
			"tcpUrgTotalCount(223)<unsigned64>[8]",
			"ipTotalLength(224)<unsigned64>[8]",
			"postNATSourceIPv4Address(225)<ipv4Address>[4]",
			"postNATDestinationIPv4Address(226)<ipv4Address>[4]",
			"postNAPTSourceTransportPort(227)<unsigned16>[2]",
			"postNAPTDestinationTransportPort(228)<unsigned16>[2]",
			"natOriginatingAddressRealm(229)<unsigned8>[1]",
			"natEvent(230)<unsigned8>[1]",
			"initiatorOctets(231)<unsigned64>[8]",
			"responderOctets(232)<unsigned64>[8]",
			"firewallEvent(233)<unsigned8>[1]",
			"ingressVRFID(234)<unsigned32>[4]",
			"egressVRFID(235)<unsigned32>[4]",
			"VRFname(236)<string>[65535]",
			"postMplsTopLabelExp(237)<unsigned8>[1]",
			"tcpWindowScale(238)<unsigned16>[2]",
			"biflowDirection(239)<unsigned8>[1]",
			"ethernetHeaderLength(240)<unsigned8>[1]",
			"ethernetPayloadLength(241)<unsigned16>[2]",
			"ethernetTotalLength(242)<unsigned16>[2]",
			"dot1qVlanId(243)<unsigned16>[2]",
			"dot1qPriority(244)<unsigned8>[1]",
			"dot1qCustomerVlanId(245)<unsigned16>[2]",
			"dot1qCustomerPriority(246)<unsigned8>[1]",
			"metroEvcId(247)<string>[65535]",
			"metroEvcType(248)<unsigned8>[1]",
			"pseudoWireId(249)<unsigned32>[4]",
			"pseudoWireType(250)<unsigned16>[2]",
			"pseudoWireControlWord(251)<unsigned32>[4]",
			"ingressPhysicalInterface(252)<unsigned32>[4]",
			"egressPhysicalInterface(253)<unsigned32>[4]",
			"postDot1qVlanId(254)<unsigned16>[2]",
			"postDot1qCustomerVlanId(255)<unsigned16>[2]",
			"ethernetType(256)<unsigned16>[2]",
			"postIpPrecedence(257)<unsigned8>[1]",
			"collectionTimeMilliseconds(258)<dateTimeMilliseconds>[8]",
			"exportSctpStreamId(259)<unsigned16>[2]",
			"maxExportSeconds(260)<dateTimeSeconds>[4]",
			"maxFlowEndSeconds(261)<dateTimeSeconds>[4]",
			"messageMD5Checksum(262)<octetArray>[65535]",
			"messageScope(263)<unsigned8>[1]",
			"minExportSeconds(264)<dateTimeSeconds>[4]",
			"minFlowStartSeconds(265)<dateTimeSeconds>[4]",
			"opaqueOctets(266)<octetArray>[65535]",
			"sessionScope(267)<unsigned8>[1]",
			"maxFlowEndMicroseconds(268)<dateTimeMicroseconds>",
			"maxFlowEndMilliseconds(269)<dateTimeMilliseconds>[8]",
			"maxFlowEndNanoseconds(270)<dateTimeNanoseconds>",
			"minFlowStartMicroseconds(271)<dateTimeMicroseconds>",
			"minFlowStartMilliseconds(272)<dateTimeMilliseconds>",
			"minFlowStartNanoseconds(273)<dateTimeNanoseconds>",
			"collectorCertificate(274)<octetArray>[65535]",
			"exporterCertificate(275)<octetArray>[65535]",
			"dataRecordsReliability(276)<boolean>[1]",
			"observationPointType(277)<unsigned8>[1]",
			"connectionCountNew(278)<unsigned32>[4]",
			"connectionSumDuration(279)<unsigned64>[8]",
			"connectionTransactionId(280)<unsigned64>[8]",
			"postNATSourceIPv6Address(281)<ipv6Address>[16]",
			"postNATDestinationIPv6Address(282)<ipv6Address>[16]",
			"natPoolId(283)<unsigned32>[4]",
			"natPoolName(284)<string>[65535]",
			"anonymizationFlags(285)<unsigned16>[2]",
			"anonymizationTechnique(286)<unsigned16>[2]",
			"informationElementIndex(287)<unsigned16>[2]",
			"p2pTechnology(288)<string>[65535]",
			"tunnelTechnology(289)<string>[65535]",
			"encryptedTechnology(290)<string>[65535]",
			"bgpValidityState(294)<unsigned8>[1]",
			"IPSecSPI(295)<unsigned32>[4]",
			"greKey(296)<unsigned32>[4]",
			"natType(297)<unsigned8>[1]",
			"initiatorPackets(298)<unsigned64>[8]",
			"responderPackets(299)<unsigned64>[8]",
			"observationDomainName(300)<string>[65535]",
			"selectionSequenceId(301)<unsigned64>[8]",
			"selectorId(302)<unsigned64>[8]",
			"informationElementId(303)<unsigned16>[2]",
			"selectorAlgorithm(304)<unsigned16>[2]",
			"samplingPacketInterval(305)<unsigned32>[4]",
			"samplingPacketSpace(306)<unsigned32>[4]",
			"samplingTimeInterval(307)<unsigned32>[4]",
			"samplingTimeSpace(308)<unsigned32>[4]",
			"samplingSize(309)<unsigned32>[4]",
			"samplingPopulation(310)<unsigned32>[4]",
			"samplingProbability(311)<float64>[8]",
			"dataLinkFrameSize(312)<unsigned16>[2]",
			"ipHeaderPacketSection(313)<octetArray>[65535]",
			"ipPayloadPacketSection(314)<octetArray>[65535]",
			"dataLinkFrameSection(315)<octetArray>[65535]",
			"mplsLabelStackSection(316)<octetArray>[65535]",
			"mplsPayloadPacketSection(317)<octetArray>[65535]",
			"selectorIdTotalPktsObserved(318)<unsigned64>[8]",
			"selectorIdTotalPktsSelected(319)<unsigned64>[8]",
			"absoluteError(320)<float64>[8]",
			"relativeError(321)<float64>[8]",
			"observationTimeSeconds(322)<dateTimeSeconds>[4]",
			"observationTimeMilliseconds(323)<dateTimeMilliseconds>",
			"observationTimeMicroseconds(324)<dateTimeMicroseconds>",
			"observationTimeNanoseconds(325)<dateTimeNanoseconds>",
			"digestHashValue(326)<unsigned64>[8]",
			"hashIPPayloadOffset(327)<unsigned64>[8]",
			"hashIPPayloadSize(328)<unsigned64>[8]",
			"hashOutputRangeMin(329)<unsigned64>[8]",
			"hashOutputRangeMax(330)<unsigned64>[8]",
			"hashSelectedRangeMin(331)<unsigned64>[8]",
			"hashSelectedRangeMax(332)<unsigned64>[8]",
			"hashDigestOutput(333)<boolean>[1]",
			"hashInitialiserValue(334)<unsigned64>[8]",
			"selectorName(335)<string>[65535]",
			"upperCILimit(336)<float64>[8]",
			"lowerCILimit(337)<float64>[8]",
			"confidenceLevel(338)<float64>[8]",
			"informationElementDataType(339)<unsigned8>[1]",
			"informationElementDescription(340)<string>[65535]",
			"informationElementName(341)<string>[65535]",
			"informationElementRangeBegin(342)<unsigned64>[8]",
			"informationElementRangeEnd(343)<unsigned64>[8]",
			"informationElementSemantics(344)<unsigned8>[1]",
			"informationElementUnits(345)<unsigned16>[2]",
			"privateEnterpriseNumber(346)<unsigned32>[4]",
			"virtualStationInterfaceId(347)<octetArray>[65535]",
			"virtualStationInterfaceName(348)<string>[65535]",
			"virtualStationUUID(349)<octetArray>[65535]",
			"virtualStationName(350)<string>[65535]",
			"layer2SegmentId(351)<unsigned64>[8]",
			"layer2OctetDeltaCount(352)<unsigned64>[8]",
			"layer2OctetTotalCount(353)<unsigned64>[8]",
			"ingressUnicastPacketTotalCount(354)<unsigned64>[8]",
			"ingressMulticastPacketTotalCount(355)<unsigned64>[8]",
			"ingressBroadcastPacketTotalCount(356)<unsigned64>[8]",
			"egressUnicastPacketTotalCount(357)<unsigned64>[8]",
			"egressBroadcastPacketTotalCount(358)<unsigned64>[8]",
			"monitoringIntervalStartMilliSeconds(359)<dateTimeMilliseconds>[8]",
			"monitoringIntervalEndMilliSeconds(360)<dateTimeMilliseconds>[8]",
			"portRangeStart(361)<unsigned16>[2]",
			"portRangeEnd(362)<unsigned16>[2]",
			"portRangeStepSize(363)<unsigned16>[2]",
			"portRangeNumPorts(364)<unsigned16>[2]",
			"staMacAddress(365)<macAddress>[6]",
			"staIPv4Address(366)<ipv4Address>[4]",
			"wtpMacAddress(367)<macAddress>[6]",
			"ingressInterfaceType(368)<unsigned32>[4]",
			"egressInterfaceType(369)<unsigned32>[4]",
			"rtpSequenceNumber(370)<unsigned16>[2]",
			"userName(371)<string>[65535]",
			"applicationCategoryName(372)<string>[65535]",
			"applicationSubCategoryName(373)<string>[65535]",
			"applicationGroupName(374)<string>[65535]",
			"originalFlowsPresent(375)<unsigned64>[8]",
			"originalFlowsInitiated(376)<unsigned64>[8]",
			"originalFlowsCompleted(377)<unsigned64>[8]",
			"distinctCountOfSourceIPAddress(378)<unsigned64>[8]",
			"distinctCountOfDestinationIPAddress(379)<unsigned64>[8]",
			"distinctCountOfSourceIPv4Address(380)<unsigned32>[4]",
			"distinctCountOfDestinationIPv4Address(381)<unsigned32>[4]",
			"distinctCountOfSourceIPv6Address(382)<unsigned64>[8]",
			"distinctCountOfDestinationIPv6Address(383)<unsigned64>[8]",
			"valueDistributionMethod(384)<unsigned8>[1]",
			"rfc3550JitterMilliseconds(385)<unsigned32>[4]",
			"rfc3550JitterMicroseconds(386)<unsigned32>[4]",
			"rfc3550JitterNanoseconds(387)<unsigned32>[4]",
			"dot1qDEI(388)<boolean>[1]",
			"dot1qCustomerDEI(389)<boolean>[1]",
			"flowSelectorAlgorithm(390)<unsigned16>",
			"flowSelectedOctetDeltaCount(391)<unsigned64>",
			"flowSelectedPacketDeltaCount(392)<unsigned64>",
			"flowSelectedFlowDeltaCount(393)<unsigned64>",
			"selectorIDTotalFlowsObserved(394)<unsigned64>",
			"selectorIDTotalFlowsSelected(395)<unsigned64>",
			"samplingFlowInterval(396)<unsigned64>",
			"samplingFlowSpacing(397)<unsigned64>",
			"flowSamplingTimeInterval(398)<unsigned64>",
			"flowSamplingTimeSpacing(399)<unsigned64>",
			"hashFlowDomain(400)<unsigned16>",
			"transportOctetDeltaCount(401)<unsigned64>",
			"transportPacketDeltaCount(402)<unsigned64>",
			"originalExporterIPv4Address(403)<ipv4Address>",
			"originalExporterIPv6Address(404)<ipv6Address>",
			"originalObservationDomainId(405)<unsigned32>",
			"intermediateProcessId(406)<unsigned32>",
			"ignoredDataRecordTotalCount(407)<unsigned64>",
			"dataLinkFrameType(408)<unsigned16>",
			"sectionOffset(409)<unsigned16>",
			"sectionExportedOctets(410)<unsigned16>",
			"dot1qServiceInstanceTag(411)<octetArray>",
			"dot1qServiceInstanceId(412)<unsigned32>",
			"dot1qServiceInstancePriority(413)<unsigned8>",
			"dot1qCustomerSourceMacAddress(414)<macAddress>",
			"dot1qCustomerDestinationMacAddress(415)<macAddress>",
			"l2OctetDeltaCount(416)<unsigned64>",
			"postL2OctetDeltaCount(417)<unsigned64>",
			"postMCastL2OctetDeltaCount(418)<unsigned64>",
			"l2OctetTotalCount(419)<unsigned64>",
			"postL2OctetTotalCount(420)<unsigned64>",
			"postMCastL2OctetTotalCount(421)<unsigned64>",
			"minimumL2TotalLength(422)<unsigned64>",
			"maximumL2TotalLength(423)<unsigned64>",
			"droppedL2OctetDeltaCount(424)<unsigned64>",
			"droppedL2OctetTotalCount(425)<unsigned64>",
			"ignoredL2OctetTotalCount(426)<unsigned64>",
			"notSentL2OctetTotalCount(427)<unsigned64>",
			"l2OctetDeltaSumOfSquares(428)<unsigned64>",
			"l2OctetTotalSumOfSquares(429)<unsigned64>"
		};	 

		int cnt = sizeof(items) / sizeof(std::string);
		for (int i=0; i<cnt; i++)
			add(items[i]);
	}

  void InfoModel::default5103() {
    std::lock_guard<std::recursive_mutex> locker(lock);

    defaultIPFIX();

	 const std::string items[] = {
		"reverseOctetDeltaCount(29305/1)<unsigned64>[8]",
		"reversePacketDeltaCount(29305/2)<unsigned64>[8]",
		"reverseDeltaFlowCount(29305/3)<unsigned64>[8]",
		"reverseProtocolIdentifier(29305/4)<unsigned8>[1]",
		"reverseIpClassOfService(29305/5)<unsigned8>[1]",
		"reverseTcpControlBits(29305/6)<unsigned8>[1]",
		"reverseSourceTransportPort(29305/7)<unsigned16>[2]",
		"reverseSourceIPv4Address(29305/8)<ipv4Address>[4]",
		"reverseSourceIPv4PrefixLength(29305/9)<unsigned8>[1]",
		"reverseIngressInterface(29305/10)<unsigned32>[4]",
		"reverseDestinationTransportPort(29305/11)<unsigned16>[2]",
		"reverseDestinationIPv4Address(29305/12)<ipv4Address>[4]",
		"reverseDestinationIPv4PrefixLength(29305/13)<unsigned8>[1]",
		"reverseEgressInterface(29305/14)<unsigned32>[4]",
		"reverseIpNextHopIPv4Address(29305/15)<ipv4Address>[4]",
		"reverseBgpSourceAsNumber(29305/16)<unsigned32>[4]",
		"reverseBgpDestinationAsNumber(29305/17)<unsigned32>[4]",
		"reverseBgpNextHopIPv4Address(29305/18)<ipv4Address>[4]",
		"reversePostMCastPacketDeltaCount(29305/19)<unsigned64>[8]",
		"reversePostMCastOctetDeltaCount(29305/20)<unsigned64>[8]",
		"reverseFlowEndSysUpTime(29305/21)<unsigned32>[4]",
		"reverseFlowStartSysUpTime(29305/22)<unsigned32>[4]",
		"reversePostOctetDeltaCount(29305/23)<unsigned64>[8]",
		"reversePostPacketDeltaCount(29305/24)<unsigned64>[8]",
		"reverseMinimumIpTotalLength(29305/25)<unsigned64>[8]",
		"reverseMaximumIpTotalLength(29305/26)<unsigned64>[8]",
		"reverseSourceIPv6Address(29305/27)<ipv6Address>[16]",
		"reverseDestinationIPv6Address(29305/28)<ipv6Address>[16]",
		"reverseSourceIPv6PrefixLength(29305/29)<unsigned8>[1]",
		"reverseDestinationIPv6PrefixLength(29305/30)<unsigned8>[1]",
		"reverseFlowLabelIPv6(29305/31)<unsigned32>[4]",
		"reverseIcmpTypeCodeIPv4(29305/32)<unsigned16>[2]",
		"reverseIgmpType(29305/33)<unsigned8>[1]",
		"reverseFlowActiveTimeout(29305/36)<unsigned16>[2]",
		"reverseFlowIdleTimeout(29305/37)<unsigned16>[2]",
		"reverseExportedOctetTotalCount(29305/40)<unsigned64>[8]",
		"reverseExportedMessageTotalCount(29305/41)<unsigned64>[8]",
		"reverseExportedFlowRecordTotalCount(29305/42)<unsigned64>[8]",
		"reverseSourceIPv4Prefix(29305/44)<ipv4Address>[4]",
		"reverseDestinationIPv4Prefix(29305/45)<ipv4Address>[4]",
		"reverseMplsTopLabelType(29305/46)<unsigned8>[1]",
		"reverseMplsTopLabelIPv4Address(29305/47)<ipv4Address>[4]",
		"reverseMinimumTTL(29305/52)<unsigned8>[1]",
		"reverseMaximumTTL(29305/53)<unsigned8>[1]",
		"reverseFragmentIdentification(29305/54)<unsigned32>[4]",
		"reversePostIpClassOfService(29305/55)<unsigned8>[1]",
		"reverseSourceMacAddress(29305/56)<macAddress>[6]",
		"reversePostDestinationMacAddress(29305/57)<macAddress>[6]",
		"reverseVlanId(29305/58)<unsigned16>[2]",
		"reversePostVlanId(29305/59)<unsigned16>[2]",
		"reverseIpVersion(29305/60)<unsigned8>[1]",
		"reverseFlowDirection(29305/61)<unsigned8>[1]",
		"reverseIpNextHopIPv6Address(29305/62)<ipv6Address>[16]",
		"reverseBgpNextHopIPv6Address(29305/63)<ipv6Address>[16]",
		"reverseIpv6ExtensionHeaders(29305/64)<unsigned32>[4]",
		"reverseMplsTopLabelStackSection(29305/70)<octetArray>[65535]",
		"reverseMplsLabelStackSection2(29305/71)<octetArray>[65535]",
		"reverseMplsLabelStackSection3(29305/72)<octetArray>[65535]",
		"reverseMplsLabelStackSection4(29305/73)<octetArray>[65535]",
		"reverseMplsLabelStackSection5(29305/74)<octetArray>[65535]",
		"reverseMplsLabelStackSection6(29305/75)<octetArray>[65535]",
		"reverseMplsLabelStackSection7(29305/76)<octetArray>[65535]",
		"reverseMplsLabelStackSection8(29305/77)<octetArray>[65535]",
		"reverseMplsLabelStackSection9(29305/78)<octetArray>[65535]",
		"reverseMplsLabelStackSection10(29305/79)<octetArray>[65535]",
		"reverseDestinationMacAddress(29305/80)<macAddress>[6]",
		"reversePostSourceMacAddress(29305/81)<macAddress>[6]",
		"reverseInterfaceName(29305/82)<string>[65535]",
		"reverseInterfaceDescription(29305/83)<string>[65535]",
		"reverseOctetTotalCount(29305/85)<unsigned64>[8]",
		"reversePacketTotalCount(29305/86)<unsigned64>[8]",
		"reverseFragmentOffset(29305/88)<unsigned16>[2]",
		"reverseMplsVpnRouteDistinguisher(29305/90)<octetArray>[65535]",
		"reverseMplsTopLabelPrefixLength(29305/91)<unsigned8>[1]",
		"reverseApplicationDescription(29305/94)<string>[65535]",
		"reverseApplicationId(29305/95)<octetArray>[65535]",
		"reverseApplicationName(29305/96)<string>[65535]",
		"reversePostIpDiffServCodePoint(29305/98)<unsigned8>[1]",
		"reverseMulticastReplicationFactor(29305/99)<unsigned32>[4]",
		"reverseClassificationEngineId(29305/101)<unsigned8>[1]",
		"reverseBgpNextAdjacentAsNumber(29305/128)<unsigned32>[4]",
		"reverseBgpPrevAdjacentAsNumber(29305/129)<unsigned32>[4]",
		"reverseExporterIPv4Address(29305/130)<ipv4Address>[4]",
		"reverseExporterIPv6Address(29305/131)<ipv6Address>[16]",
		"reverseDroppedOctetDeltaCount(29305/132)<unsigned64>[8]",
		"reverseDroppedPacketDeltaCount(29305/133)<unsigned64>[8]",
		"reverseDroppedOctetTotalCount(29305/134)<unsigned64>[8]",
		"reverseDroppedPacketTotalCount(29305/135)<unsigned64>[8]",
		"reverseFlowEndReason(29305/136)<unsigned8>[1]",
		"reverseCommonPropertiesId(29305/137)<unsigned64>[8]",
		"reverseObservationPointId(29305/138)<unsigned64>[8]",
		"reverseIcmpTypeCodeIPv6(29305/139)<unsigned16>[2]",
		"reverseMplsTopLabelIPv6Address(29305/140)<ipv6Address>[16]",
		"reverseLineCardId(29305/141)<unsigned32>[4]",
		"reversePortId(29305/142)<unsigned32>[4]",
		"reverseMeteringProcessId(29305/143)<unsigned32>[4]",
		"reverseExportingProcessId(29305/144)<unsigned32>[4]",
		"reverseTemplateId(29305/145)<unsigned16>[2]",
		"reverseWlanChannelId(29305/146)<unsigned8>[1]",
		"reverseWlanSSID(29305/147)<string>[65535]",
		"reverseFlowId(29305/148)<unsigned64>[8]",
		"reverseObservationDomainId(29305/149)<unsigned32>[4]",
		"reverseFlowStartSeconds(29305/150)<dateTimeSeconds>[4]",
		"reverseFlowEndSeconds(29305/151)<dateTimeSeconds>[4]",
		"reverseFlowStartMilliseconds(29305/152)<dateTimeMilliseconds>[8]",
		"reverseFlowEndMilliseconds(29305/153)<dateTimeMilliseconds>[8]",
		"reverseFlowStartMicroseconds(29305/154)<dateTimeMicroseconds>",
		"reverseFlowEndMicroseconds(29305/155)<dateTimeMicroseconds>",
		"reverseFlowStartNanoseconds(29305/156)<dateTimeNanoseconds>",
		"reverseFlowEndNanoseconds(29305/157)<dateTimeNanoseconds>",
		"reverseFlowStartDeltaMicroseconds(29305/158)<unsigned32>[4]",
		"reverseFlowEndDeltaMicroseconds(29305/159)<unsigned32>[4]",
		"reverseSystemInitTimeMilliseconds(29305/160)<dateTimeMilliseconds>[8]",
		"reverseFlowDurationMilliseconds(29305/161)<unsigned32>[4]",
		"reverseFlowDurationMicroseconds(29305/162)<unsigned32>[4]",
		"reverseObservedFlowTotalCount(29305/163)<unsigned64>[8]",
		"reverseIgnoredPacketTotalCount(29305/164)<unsigned64>[8]",
		"reverseIgnoredOctetTotalCount(29305/165)<unsigned64>[8]",
		"reverseNotSentFlowTotalCount(29305/166)<unsigned64>[8]",
		"reverseNotSentPacketTotalCount(29305/167)<unsigned64>[8]",
		"reverseNotSentOctetTotalCount(29305/168)<unsigned64>[8]",
		"reverseDestinationIPv6Prefix(29305/169)<ipv6Address>[16]",
		"reverseSourceIPv6Prefix(29305/170)<ipv6Address>[16]",
		"reversePostOctetTotalCount(29305/171)<unsigned64>[8]",
		"reversePostPacketTotalCount(29305/172)<unsigned64>[8]",
		"reverseFlowKeyIndicator(29305/173)<unsigned64>[8]",
		"reversePostMCastPacketTotalCount(29305/174)<unsigned64>[8]",
		"reversePostMCastOctetTotalCount(29305/175)<unsigned64>[8]",
		"reverseIcmpTypeIPv4(29305/176)<unsigned8>[1]",
		"reverseIcmpCodeIPv4(29305/177)<unsigned8>[1]",
		"reverseIcmpTypeIPv6(29305/178)<unsigned8>[1]",
		"reverseIcmpCodeIPv6(29305/179)<unsigned8>[1]",
		"reverseUdpSourcePort(29305/180)<unsigned16>[2]",
		"reverseUdpDestinationPort(29305/181)<unsigned16>[2]",
		"reverseTcpSourcePort(29305/182)<unsigned16>[2]",
		"reverseTcpDestinationPort(29305/183)<unsigned16>[2]",
		"reverseTcpSequenceNumber(29305/184)<unsigned32>[4]",
		"reverseTcpAcknowledgementNumber(29305/185)<unsigned32>[4]",
		"reverseTcpWindowSize(29305/186)<unsigned16>[2]",
		"reverseTcpUrgentPointer(29305/187)<unsigned16>[2]",
		"reverseTcpHeaderLength(29305/188)<unsigned8>[1]",
		"reverseIpHeaderLength(29305/189)<unsigned8>[1]",
		"reverseTotalLengthIPv4(29305/190)<unsigned16>[2]",
		"reversePayloadLengthIPv6(29305/191)<unsigned16>[2]",
		"reverseIpTTL(29305/192)<unsigned8>[1]",
		"reverseNextHeaderIPv6(29305/193)<unsigned8>[1]",
		"reverseMplsPayloadLength(29305/194)<unsigned32>[4]",
		"reverseIpDiffServCodePoint(29305/195)<unsigned8>[1]",
		"reverseIpPrecedence(29305/196)<unsigned8>[1]",
		"reverseFragmentFlags(29305/197)<unsigned8>[1]",
		"reverseOctetDeltaSumOfSquares(29305/198)<unsigned64>[8]",
		"reverseOctetTotalSumOfSquares(29305/199)<unsigned64>[8]",
		"reverseMplsTopLabelTTL(29305/200)<unsigned8>[1]",
		"reverseMplsLabelStackLength(29305/201)<unsigned32>[4]",
		"reverseMplsLabelStackDepth(29305/202)<unsigned32>[4]",
		"reverseMplsTopLabelExp(29305/203)<unsigned8>[1]",
		"reverseIpPayloadLength(29305/204)<unsigned32>[4]",
		"reverseUdpMessageLength(29305/205)<unsigned16>[2]",
		"reverseIsMulticast(29305/206)<unsigned8>[1]",
		"reverseIpv4IHL(29305/207)<unsigned8>[1]",
		"reverseIpv4Options(29305/208)<unsigned32>[4]",
		"reverseTcpOptions(29305/209)<unsigned64>[8]",
		"reversePaddingOctets(29305/210)<octetArray>[65535]",
		"reverseCollectorIPv4Address(29305/211)<ipv4Address>[4]",
		"reverseCollectorIPv6Address(29305/212)<ipv6Address>[16]",
		"reverseExportInterface(29305/213)<unsigned32>[4]",
		"reverseExportProtocolVersion(29305/214)<unsigned8>[1]",
		"reverseExportTransportProtocol(29305/215)<unsigned8>[1]",
		"reverseCollectorTransportPort(29305/216)<unsigned16>[2]",
		"reverseExporterTransportPort(29305/217)<unsigned16>[2]",
		"reverseTcpSynTotalCount(29305/218)<unsigned64>[8]",
		"reverseTcpFinTotalCount(29305/219)<unsigned64>[8]",
		"reverseTcpRstTotalCount(29305/220)<unsigned64>[8]",
		"reverseTcpPshTotalCount(29305/221)<unsigned64>[8]",
		"reverseTcpAckTotalCount(29305/222)<unsigned64>[8]",
		"reverseTcpUrgTotalCount(29305/223)<unsigned64>[8]",
		"reverseIpTotalLength(29305/224)<unsigned64>[8]",
		"reversePostNATSourceIPv4Address(29305/225)<ipv4Address>[4]",
		"reversePostNATDestinationIPv4Address(29305/226)<ipv4Address>[4]",
		"reversePostNAPTSourceTransportPort(29305/227)<unsigned16>[2]",
		"reversePostNAPTDestinationTransportPort(29305/228)<unsigned16>[2]",
		"reverseNatOriginatingAddressRealm(29305/229)<unsigned8>[1]",
		"reverseNatEvent(29305/230)<unsigned8>[1]",
		"reverseInitiatorOctets(29305/231)<unsigned64>[8]",
		"reverseResponderOctets(29305/232)<unsigned64>[8]",
		"reverseFirewallEvent(29305/233)<unsigned8>[1]",
		"reverseIngressVRFID(29305/234)<unsigned32>[4]",
		"reverseEgressVRFID(29305/235)<unsigned32>[4]",
		"reverseVRFname(29305/236)<string>[65535]",
		"reversePostMplsTopLabelExp(29305/237)<unsigned8>[1]",
		"reverseTcpWindowScale(29305/238)<unsigned16>[2]",
		"reverseBiflowDirection(29305/239)<unsigned8>[1]",
		"reverseEthernetHeaderLength(29305/240)<unsigned8>[1]",
		"reverseEthernetPayloadLength(29305/241)<unsigned16>[2]",
		"reverseEthernetTotalLength(29305/242)<unsigned16>[2]",
		"reverseDot1qVlanId(29305/243)<unsigned16>[2]",
		"reverseDot1qPriority(29305/244)<unsigned8>[1]",
		"reverseDot1qCustomerVlanId(29305/245)<unsigned16>[2]",
		"reverseDot1qCustomerPriority(29305/246)<unsigned8>[1]",
		"reverseMetroEvcId(29305/247)<string>[65535]",
		"reverseMetroEvcType(29305/248)<unsigned8>[1]",
		"reversePseudoWireId(29305/249)<unsigned32>[4]",
		"reversePseudoWireType(29305/250)<unsigned16>[2]",
		"reversePseudoWireControlWord(29305/251)<unsigned32>[4]",
		"reverseIngressPhysicalInterface(29305/252)<unsigned32>[4]",
		"reverseEgressPhysicalInterface(29305/253)<unsigned32>[4]",
		"reversePostDot1qVlanId(29305/254)<unsigned16>[2]",
		"reversePostDot1qCustomerVlanId(29305/255)<unsigned16>[2]",
		"reverseEthernetType(29305/256)<unsigned16>[2]",
		"reversePostIpPrecedence(29305/257)<unsigned8>[1]",
		"reverseCollectionTimeMilliseconds(29305/258)<dateTimeMilliseconds>[8]",
		"reverseExportSctpStreamId(29305/259)<unsigned16>[2]",
		"reverseMaxExportSeconds(29305/260)<dateTimeSeconds>[4]",
		"reverseMaxFlowEndSeconds(29305/261)<dateTimeSeconds>[4]",
		"reverseMessageMD5Checksum(29305/262)<octetArray>[65535]",
		"reverseMessageScope(29305/263)<unsigned8>[1]",
		"reverseMinExportSeconds(29305/264)<dateTimeSeconds>[4]",
		"reverseMinFlowStartSeconds(29305/265)<dateTimeSeconds>[4]",
		"reverseOpaqueOctets(29305/266)<octetArray>[65535]",
		"reverseSessionScope(29305/267)<unsigned8>[1]",
		"reverseMaxFlowEndMicroseconds(29305/268)<dateTimeMicroseconds>",
		"reverseMaxFlowEndMilliseconds(29305/269)<dateTimeMilliseconds>",
		"reverseMaxFlowEndNanoseconds(29305/270)<dateTimeNanoseconds>",
		"reverseMinFlowStartMicroseconds(29305/271)<dateTimeMicroseconds>",
		"reverseMinFlowStartMilliseconds(29305/272)<dateTimeMilliseconds>",
		"reverseMinFlowStartNanoseconds(29305/273)<dateTimeNanoseconds>",
		"reverseCollectorCertificate(29305/274)<octetArray>[65535]",
		"reverseExporterCertificate(29305/275)<octetArray>[65535]",
		"reverseDataRecordsReliability(29305/276)<boolean>[1]",
		"reverseObservationPointType(29305/277)<unsigned8>[1]",
		"reverseConnectionCountNew(29305/278)<unsigned32>[4]",
		"reverseConnectionSumDuration(29305/279)<unsigned64>[8]",
		"reverseConnectionTransactionId(29305/280)<unsigned64>[8]",
		"reversePostNATSourceIPv6Address(29305/281)<ipv6Address>[16]",
		"reversePostNATDestinationIPv6Address(29305/282)<ipv6Address>[16]",
		"reverseNatPoolId(29305/283)<unsigned32>[4]",
		"reverseNatPoolName(29305/284)<string>[65535]",
		"reverseAnonymizationFlags(29305/285)<unsigned16>[2]",
		"reverseAnonymizationTechnique(29305/286)<unsigned16>[2]",
		"reverseInformationElementIndex(29305/287)<unsigned16>[2]",
		"reverseP2PTechnology(29305/288)<string>[65535]",
		"reverseTunnelTechnology(29305/289)<string>[65535]",
		"reverseEncryptedTechnology(29305/290)<string>[65535]",
		"reverseBgpValidityState(29305/294)<unsigned8>[1]",
		"reverseIPSecSPI(29305/295)<unsigned32>[4]",
		"reverseGreKey(29305/296)<unsigned32>[4]",
		"reverseNatType(29305/297)<unsigned8>[1]",
		"reverseInitiatorPackets(29305/298)<unsigned64>[8]",
		"reverseResponderPackets(29305/299)<unsigned64>[8]",
		"reverseObservationDomainName(29305/300)<string>[65535]",
		"reverseSelectionSequenceId(29305/301)<unsigned64>[8]",
		"reverseSelectorId(29305/302)<unsigned64>[8]",
		"reverseInformationElementId(29305/303)<unsigned16>[2]",
		"reverseSelectorAlgorithm(29305/304)<unsigned16>[2]",
		"reverseSamplingPacketInterval(29305/305)<unsigned32>[4]",
		"reverseSamplingPacketSpace(29305/306)<unsigned32>[4]",
		"reverseSamplingTimeInterval(29305/307)<unsigned32>[4]",
		"reverseSamplingTimeSpace(29305/308)<unsigned32>[4]",
		"reverseSamplingSize(29305/309)<unsigned32>[4]",
		"reverseSamplingPopulation(29305/310)<unsigned32>[4]",
		"reverseSamplingProbability(29305/311)<float64>[8]",
		"reverseDataLinkFrameSize(29305/312)<unsigned16>[2]",
		"reverseIpHeaderPacketSection(29305/313)<octetArray>[65535]",
		"reverseIpPayloadPacketSection(29305/314)<octetArray>[65535]",
		"reverseDataLinkFrameSection(29305/315)<octetArray>[65535]",
		"reverseMplsLabelStackSection(29305/316)<octetArray>[65535]",
		"reverseMplsPayloadPacketSection(29305/317)<octetArray>[65535]",
		"reverseSelectorIdTotalPktsObserved(29305/318)<unsigned64>[8]",
		"reverseSelectorIdTotalPktsSelected(29305/319)<unsigned64>[8]",
		"reverseAbsoluteError(29305/320)<float64>[8]",
		"reverseRelativeError(29305/321)<float64>[8]",
		"reverseObservationTimeSeconds(29305/322)<dateTimeSeconds>",
		"reverseObservationTimeMilliseconds(29305/323)<dateTimeMilliseconds>",
		"reverseObservationTimeMicroseconds(29305/324)<dateTimeMicroseconds>",
		"reverseObservationTimeNanoseconds(29305/325)<dateTimeNanoseconds>",
		"reverseDigestHashValue(29305/326)<unsigned64>[8]",
		"reverseHashIPPayloadOffset(29305/327)<unsigned64>[8]",
		"reverseHashIPPayloadSize(29305/328)<unsigned64>[8]",
		"reverseHashOutputRangeMin(29305/329)<unsigned64>[8]",
		"reverseHashOutputRangeMax(29305/330)<unsigned64>[8]",
		"reverseHashSelectedRangeMin(29305/331)<unsigned64>[8]",
		"reverseHashSelectedRangeMax(29305/332)<unsigned64>[8]",
		"reverseHashDigestOutput(29305/333)<boolean>[1]",
		"reverseHashInitialiserValue(29305/334)<unsigned64>[8]",
		"reverseSelectorName(29305/335)<string>[65535]",
		"reverseUpperCILimit(29305/336)<float64>[8]",
		"reverseLowerCILimit(29305/337)<float64>[8]",
		"reverseConfidenceLevel(29305/338)<float64>[8]",
		"reverseInformationElementDataType(29305/339)<unsigned8>[1]",
		"reverseInformationElementDescription(29305/340)<string>[65535]",
		"reverseInformationElementName(29305/341)<string>[65535]",
		"reverseInformationElementRangeBegin(29305/342)<unsigned64>[8]",
		"reverseInformationElementRangeEnd(29305/343)<unsigned64>[8]",
		"reverseInformationElementSemantics(29305/344)<unsigned8>[1]",
		"reverseInformationElementUnits(29305/345)<unsigned16>[2]",
		"reversePrivateEnterpriseNumber(29305/346)<unsigned32>[4]",
		"reverseVirtualStationInterfaceId(29305/347)<octetArray>[65535]",
		"reverseVirtualStationInterfaceName(29305/348)<string>[65535]",
		"reverseVirtualStationUUID(29305/349)<octetArray>[65535]",
		"reverseVirtualStationName(29305/350)<string>[65535]",
		"reverseLayer2SegmentId(29305/351)<unsigned64>[8]",
		"reverseLayer2OctetDeltaCount(29305/352)<unsigned64>[8]",
		"reverseLayer2OctetTotalCount(29305/353)<unsigned64>[8]",
		"reverseIngressUnicastPacketTotalCount(29305/354)<unsigned64>[8]",
		"reverseIngressMulticastPacketTotalCount(29305/355)<unsigned64>[8]",
		"reverseIngressBroadcastPacketTotalCount(29305/356)<unsigned64>[8]",
		"reverseEgressUnicastPacketTotalCount(29305/357)<unsigned64>[8]",
		"reverseEgressBroadcastPacketTotalCount(29305/358)<unsigned64>[8]",
		"reverseMonitoringIntervalStartMilliSeconds(29305/359)<dateTimeMilliseconds>[8]",
		"reverseMonitoringIntervalEndMilliSeconds(29305/360)<dateTimeMilliseconds>[8]",
		"reversePortRangeStart(29305/361)<unsigned16>[2]",
		"reversePortRangeEnd(29305/362)<unsigned16>[2]",
		"reversePortRangeStepSize(29305/363)<unsigned16>[2]",
		"reversePortRangeNumPorts(29305/364)<unsigned16>[2]",
		"reverseStaMacAddress(29305/365)<macAddress>[6]",
		"reverseStaIPv4Address(29305/366)<ipv4Address>[4]",
		"reverseWtpMacAddress(29305/367)<macAddress>[6]",
		"reverseIngressInterfaceType(29305/368)<unsigned32>[4]",
		"reverseEgressInterfaceType(29305/369)<unsigned32>[4]",
		"reverseRtpSequenceNumber(29305/370)<unsigned16>[2]",
		"reverseUserName(29305/371)<string>[65535]",
		"reverseApplicationCategoryName(29305/372)<string>[65535]",
		"reverseApplicationSubCategoryName(29305/373)<string>[65535]",
		"reverseApplicationGroupName(29305/374)<string>[65535]",
		"reverseOriginalFlowsPresent(29305/375)<unsigned64>[8]",
		"reverseOriginalFlowsInitiated(29305/376)<unsigned64>[8]",
		"reverseOriginalFlowsCompleted(29305/377)<unsigned64>[8]",
		"reverseDistinctCountOfSourceIPAddress(29305/378)<unsigned64>[8]",
		"reverseDistinctCountOfDestinationIPAddress(29305/379)<unsigned64>[8]",
		"reverseDistinctCountOfSourceIPv4Address(29305/380)<unsigned32>[4]",
		"reverseDistinctCountOfDestinationIPv4Address(29305/381)<unsigned32>[4]",
		"reverseDistinctCountOfSourceIPv6Address(29305/382)<unsigned64>[8]",
		"reverseDistinctCountOfDestinationIPv6Address(29305/383)<unsigned64>[8]",
		"reverseValueDistributionMethod(29305/384)<unsigned8>[1]",
		"reverseRfc3550JitterMilliseconds(29305/385)<unsigned32>[4]",
		"reverseRfc3550JitterMicroseconds(29305/386)<unsigned32>[4]",
		"reverseRfc3550JitterNanoseconds(29305/387)<unsigned32>[4]",
		"reverseDot1qDEI(29305/388)<boolean>[1]",
		"reverseDot1qCustomerDEI(29305/389)<boolean>[1]",
		"reverseFlowSelectorAlgorithm(29305/390)<unsigned16>",
		"reverseFlowSelectedOctetDeltaCount(29305/391)<unsigned64>",
		"reverseFlowSelectedPacketDeltaCount(29305/392)<unsigned64>",
		"reverseFlowSelectedFlowDeltaCount(29305/393)<unsigned64>",
		"reverseSelectorIDTotalFlowsObserved(29305/394)<unsigned64>",
		"reverseSelectorIDTotalFlowsSelected(29305/395)<unsigned64>",
		"reverseSamplingFlowInterval(29305/396)<unsigned64>",
		"reverseSamplingFlowSpacing(29305/397)<unsigned64>",
		"reverseFlowSamplingTimeInterval(29305/398)<unsigned64>",
		"reverseFlowSamplingTimeSpacing(29305/399)<unsigned64>",
		"reverseHashFlowDomain(29305/400)<unsigned16>",
		"reverseTransportOctetDeltaCount(29305/401)<unsigned64>",
		"reverseTransportPacketDeltaCount(29305/402)<unsigned64>",
		"reverseOriginalExporterIPv4Address(29305/403)<ipv4Address>",
		"reverseOriginalExporterIPv6Address(29305/404)<ipv6Address>",
		"reverseOriginalObservationDomainId(29305/405)<unsigned32>",
		"reverseIntermediateProcessId(29305/406)<unsigned32>",
		"reverseIgnoredDataRecordTotalCount(29305/407)<unsigned64>",
		"reverseDataLinkFrameType(29305/408)<unsigned16>",
		"reverseSectionOffset(29305/409)<unsigned16>",
		"reverseSectionExportedOctets(29305/410)<unsigned16>",
		"reverseDot1qServiceInstanceTag(29305/411)<octetArray>",
		"reverseDot1qServiceInstanceId(29305/412)<unsigned32>",
		"reverseDot1qServiceInstancePriority(29305/413)<unsigned8>",
		"reverseDot1qCustomerSourceMacAddress(29305/414)<macAddress>",
		"reverseDot1qCustomerDestinationMacAddress(29305/415)<macAddress>",
		"reverseL2OctetDeltaCount(29305/416)<unsigned64>",
		"reversePostL2OctetDeltaCount(29305/417)<unsigned64>",
		"reversePostMCastL2OctetDeltaCount(29305/418)<unsigned64>",
		"reverseL2OctetTotalCount(29305/419)<unsigned64>",
		"reversePostL2OctetTotalCount(29305/420)<unsigned64>",
		"reversePostMCastL2OctetTotalCount(29305/421)<unsigned64>",
		"reverseMinimumL2TotalLength(29305/422)<unsigned64>",
		"reverseMaximumL2TotalLength(29305/423)<unsigned64>",
		"reverseDroppedL2OctetDeltaCount(29305/424)<unsigned64>",
		"reverseDroppedL2OctetTotalCount(29305/425)<unsigned64>",
		"reverseIgnoredL2OctetTotalCount(29305/426)<unsigned64>",
		"reverseNotSentL2OctetTotalCount(29305/427)<unsigned64>",
		"reverseL2OctetDeltaSumOfSquares(29305/428)<unsigned64>",
		"reverseL2OctetTotalSumOfSquares(29305/429)<unsigned64>"
	};
	 
	int cnt = sizeof(items) / sizeof(std::string);
	for (int i=0; i<cnt; i++)
		add(items[i]);
}

} /* namespace libfc */
