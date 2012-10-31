/* Copyright (c) 2011-2012 ETH Zürich. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * The name of ETH Zürich nor the names of other contributors 
 *      may be used to endorse or promote products derived from this software 
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT 
 * HOLDERBE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
 * PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER 
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF 
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE
 */

#include <cassert>
#include <fstream>

#include <fcntl.h>

#include "BasicOctetArray.h"
#include "DataSetDecoder.h"
#include "FileInputSource.h"
#include "IPFIXReader.h"
#include "InfoModel.h"
#include "MatchTemplate.h"
#include "MBuf.h"
#include "RecordReceiver.h"

#include "test/TestCommon.h"

using namespace IPFIX;

static uint64_t kTimeSeqStart = 1141344000000UL; // March 3, 2006
static uint64_t kTimeSeqStep  = 1000;            // one second
static uint32_t kIPSeqStart   = 0x0A000000;      // 10.0.0.1
static uint32_t kIPSeqEnd     = 0x0AFFFFFF;      // 10.255.255.255
static uint32_t kIPSeqStep    = 1;
static uint16_t kPortSeqStart = 1;
static uint16_t kPortSeqEnd   = 65535;
static uint32_t kPortSeqStep  = 1;
static uint64_t kOctetsSeqStart = 44;
static uint64_t kOctetsSeqEnd   = 1000000000;
static uint64_t kOctetsSeqStep  = 44;

static uint16_t kFlowTemplateId = 256;
static uint16_t kObsTemplateId = 257;

static unsigned int kTestCycleCount = 100000;
static unsigned int kTestFlowPerSetCount = 222;
static unsigned int kTestObsPerSetCount = 111;

class TestFlow {
    friend std::ostream& operator<<(std::ostream& out, const TestFlow& f);

private:
    
    uint64_t        stime;
    uint64_t        etime;
    uint32_t        sip;
    uint32_t        dip;
    uint16_t        sp;
    uint16_t        dp;
    uint8_t         proto;
    uint64_t        octets;

    const InfoElement*    ie_stime;
    const InfoElement*    ie_etime;
    const InfoElement*    ie_sip;
    const InfoElement*    ie_dip;
    const InfoElement*    ie_sp;
    const InfoElement*    ie_dp;
    const InfoElement*    ie_proto;
    const InfoElement*    ie_octets;

public:
    
    TestFlow():
        stime(kTimeSeqStart),
        etime(kTimeSeqStart + kTimeSeqStep),
        sip(kIPSeqStart),
        dip(kIPSeqEnd),
        sp(kPortSeqStart),
        dp(kPortSeqEnd),
        proto(6),
        octets(kOctetsSeqStart) {}

  TestFlow(uint64_t stime,
           uint64_t etime,
           uint32_t sip,
           uint32_t dip,
           uint16_t sp,
           uint16_t dp,
           uint8_t  proto,
           uint64_t octets)
    : stime(stime),
      etime(etime),
      sip(sip),
      dip(dip),
      sp(sp),
      dp(dp),
      proto(proto),
      octets(octets) {
  }

    void incrementPattern() {
        stime += kTimeSeqStep;
        etime += kTimeSeqStep;
        sip += kIPSeqStep; if (sip > kIPSeqEnd) sip = kIPSeqStart;
        dip -= kIPSeqStep; if (dip < kIPSeqStart) sip = kIPSeqEnd;
        sp += kPortSeqStep; if (sp > kPortSeqEnd) sp = kPortSeqStart;
        dp -= kPortSeqStep; if (sp < kPortSeqStart) sp = kPortSeqEnd;
        octets += kOctetsSeqStep; 
        if (octets > kOctetsSeqEnd) octets = kOctetsSeqStart;
    }
    
    bool operator==(const TestFlow& rhs) const {
        bool ret = stime == rhs.stime
          && etime == rhs.etime
          && sip == rhs.sip
          && dip == rhs.dip
          && sp == rhs.sp
          && dp == rhs.dp 
          && proto == rhs.proto
          && octets == rhs.octets;
        if (!ret) {
          if (stime != rhs.stime)
            std::cout << "this stime = " << stime 
                      << ", rhs.stime = " << rhs.stime << std::endl;
          if (etime != rhs.etime)
            std::cout << "this etime = " << etime 
                      << ", rhs.etime = " << rhs.etime << std::endl;
          if (sip != rhs.sip)
            std::cout << "this sip = " << sip 
                      << ", rhs.sip = " << rhs.sip << std::endl;
          if (dip != rhs.dip)
            std::cout << "this dip = " << dip 
                      << ", rhs.dip = " << rhs.dip << std::endl;
          if (sp != rhs.sp)
            std::cout << "this sp = " << sp 
                      << ", rhs.sp = " << rhs.sp << std::endl;
          if (dp != rhs.dp )
            std::cout << "this dp = " << dp 
                      << ", rhs.dp = " << rhs.dp << std::endl;
          if (proto != rhs.proto)
            std::cout << "this proto = " << proto 
                      << ", rhs.proto = " << rhs.proto << std::endl;
          if (octets != rhs.octets)
            std::cout << "this octets = " << std::hex << octets
                      << ", rhs.octets = " << std::hex << rhs.octets << std::endl;
        }
        return ret;
    }

    bool operator!=(const TestFlow& rhs) const {
      return !(*this == rhs);
    }

    static void addIEs() {
    }

    void prepareExport(Exporter& e) {
        InfoModel& m = InfoModel::instance();

        ie_stime = m.lookupIE("flowStartMilliseconds");
        ie_etime = m.lookupIE("flowEndMilliseconds");
        ie_sip = m.lookupIE("sourceIPv4Address");
        ie_dip = m.lookupIE("destinationIPv4Address");
        ie_sp = m.lookupIE("sourceTransportPort");
        ie_dp = m.lookupIE("destinationTransportPort");
        ie_proto = m.lookupIE("protocolIdentifier");
        ie_octets = m.lookupIE("octetDeltaCount[4]");

        WireTemplate* t = e.getTemplate(kFlowTemplateId);
        assert(t != 0);
        t->clear();
        t->add(ie_stime);
        t->add(ie_etime);
        t->add(ie_sip);
        t->add(ie_dip);
        t->add(ie_sp);
        t->add(ie_dp);
        t->add(ie_proto);
        t->add(ie_octets);
        t->activate();
    }

    void do_export(Exporter& e) {
        e.setTemplate(kFlowTemplateId);
        e.beginRecord();
        e.putValue(ie_stime, stime);
        e.putValue(ie_etime, etime);
        e.putValue(ie_sip, sip);
        e.putValue(ie_dip, dip);
        e.putValue(ie_sp, sp);
        e.putValue(ie_dp, dp);
        e.putValue(ie_proto, proto);
        e.putValue(ie_octets, octets);
        e.exportRecord();
    }

};

std::ostream& operator<<(std::ostream& out, const TestFlow& f) {
  out << "("
      << "stime=" << f.stime
      << ",etime=" << f.etime
      << ",sip=" << f.sip
      << ",dip=" << f.dip
      << ",sp=" << f.sp
      << ",dp=" << f.dp
      << ",proto=" << f.proto
      << ",octets=" << f.octets
      << ")";
  return out;
}

std::string& obsLabelFor(uint64_t value) {
    
    static std::vector<std::string> labels;
    static bool labels_valid = false;
    
    if (!labels_valid) {
        labels_valid = true;
        labels.clear();
        labels.push_back("To-morrow,"); 
        labels.push_back("and"); 
        labels.push_back("to-morrow,"); 
        labels.push_back("and"); 
        labels.push_back("to-morrow,");
        labels.push_back("Creeps"); 
        labels.push_back("in"); 
        labels.push_back("this"); 
        labels.push_back("petty"); 
        labels.push_back("pace"); 
        labels.push_back("from"); 
        labels.push_back("day"); 
        labels.push_back("to"); 
        labels.push_back("day,");
        labels.push_back("To"); 
        labels.push_back("the"); 
        labels.push_back("last"); 
        labels.push_back("syllable"); 
        labels.push_back("of"); 
        labels.push_back("recorded"); 
        labels.push_back("time;");
    }
    
    return labels[value % labels.size()];
}


class TestObs {
    friend std::ostream& operator<<(std::ostream& out, const TestObs& o);

private:
    
    uint64_t                otime_;
    uint64_t                value_;
    std::string             label_;
    const InfoElement*      ie_otime_;
    const InfoElement*      ie_value_;
    const InfoElement*      ie_label_;

public:

    TestObs():
        otime_(kTimeSeqStart),
        value_(0),
        label_(obsLabelFor(0))
        {}

  TestObs(uint64_t otime, 
          uint64_t value,
          std::string label) 
    : otime_(otime), value_(value), label_(label) {
  }

    void incrementPattern() {
        otime_ += kTimeSeqStep;
        value_ += 1;
        label_ = obsLabelFor(value_);
    }

    bool operator== (const TestObs& rhs) const {
      bool ret = otime_ == rhs.otime_
         && label_ == rhs.label_
         && value_ == rhs.value_;
      if (!ret) {
        if (otime_ != rhs.otime_)
          std::cerr << "this otime = " << otime_ 
                    << ", rhs.otime = " << rhs.otime_ << std::endl;
        if (label_ != rhs.label_)
          std::cerr << "this label = " << label_
                    << ", rhs.label = " << rhs.label_ << std::endl;
        if (value_ != rhs.value_)
          std::cerr << "this value = " << value_
                    << ", rhs.value = " << rhs.value_ << std::endl;
      }
      return ret;
    }

    bool operator!=(const TestObs& rhs) const {
      return !(*this == rhs);
    }

    static void addIEs() {
        InfoModel& m = InfoModel::instance();
        m.add("observationValue(35566/804)<unsigned64>[8]");
        m.add("observationLabel(35566/805)<string>[v]");
    }

    void prepareExport(Exporter& e) {
        InfoModel& m = InfoModel::instance();
        
        ie_otime_ = m.lookupIE("observationTimeMilliseconds");
        ie_value_ = m.lookupIE("observationValue");
        ie_label_ = m.lookupIE("observationLabel");
        
        WireTemplate* t = e.getTemplate(kObsTemplateId);
        t->clear();
        t->add(ie_otime_);
        t->add(ie_value_);
        t->add(ie_label_);
        t->activate();
    }

    void do_export(Exporter& e) {
        e.setTemplate(kObsTemplateId);
        e.beginRecord();
        e.reserveVarlen(ie_label_, label_.size());
        e.commitVarlen();
        e.putValue(ie_otime_, otime_);
        e.putValue(ie_value_, value_);
        e.putValue(ie_label_, label_);
        e.exportRecord();
    }
};

std::ostream& operator<<(std::ostream& out, const TestObs& o) {
  out << "("
      << "otime=" << o.otime_
      << ",value=" << o.value_
      << ",label=\"" << o.label_ << "\""
      << ")";
  return out;
}

class TestFlowReceiver : public RecordReceiver {
private:
  TestFlow f_;
  bool pass_;
  unsigned int rec_count;

    const InfoElement*    ie_stime;
    const InfoElement*    ie_etime;
    const InfoElement*    ie_sip;
    const InfoElement*    ie_dip;
    const InfoElement*    ie_sp;
    const InfoElement*    ie_dp;
    const InfoElement*    ie_proto;
    const InfoElement*    ie_octets;

    MatchTemplate t;

public:
  TestFlowReceiver() 
    : pass_(true), 
      rec_count(0),
      ie_stime(InfoModel::instance().lookupIE("flowStartMilliseconds")),
      ie_etime(InfoModel::instance().lookupIE("flowEndMilliseconds")),
      ie_sip(InfoModel::instance().lookupIE("sourceIPv4Address")),
      ie_dip(InfoModel::instance().lookupIE("destinationIPv4Address")),
      ie_sp(InfoModel::instance().lookupIE("sourceTransportPort")),
      ie_dp(InfoModel::instance().lookupIE("destinationTransportPort")),
      ie_proto(InfoModel::instance().lookupIE("protocolIdentifier")),
      ie_octets(InfoModel::instance().lookupIE("octetDeltaCount[4]")) {
    
    assert(ie_stime != 0);
    assert(ie_etime != 0);
    assert(ie_sip != 0);
    assert(ie_dip != 0);
    assert(ie_sp != 0);
    assert(ie_dp != 0);
    assert(ie_proto != 0);
    assert(ie_octets != 0);

    t.add(ie_stime);
    t.add(ie_etime);
    t.add(ie_sip);
    t.add(ie_dip);
    t.add(ie_sp);
    t.add(ie_dp);
    t.add(ie_proto);
    t.add(ie_octets);
    t.activate();
  }

  IETemplate* get_template() {
    return &t;
  }

  bool is_passing() const { 
    return pass_;
  }

  unsigned int get_rec_count() const {
    return rec_count;
  }

  void receiveRecord()  {
    rec_count++;

    uint64_t stime;
    uint64_t etime;
    uint32_t sip;
    uint32_t dip;
    uint16_t sp;
    uint16_t dp;
    uint8_t  proto;
    uint64_t octets;

    if (getValue(ie_stime, stime)
        && getValue(ie_etime, etime)
        && getValue(ie_sip, sip)
        && getValue(ie_dip, dip)
        && getValue(ie_sp, sp)
        && getValue(ie_dp, dp)
        && getValue(ie_proto, proto)
        && getValue(ie_octets, octets)) {
      TestFlow f(stime, etime, sip, dip, sp, dp, proto, octets);
      if (f_ != f)
        pass_ = false;
    } else {
      std::cerr << "some getValue() returned false" << std::endl;
      pass_ = false;
    }
    f_.incrementPattern();
  }
};

class TestObsReceiver : public RecordReceiver {
private:
  TestObs o_;
  bool pass_;
  unsigned int rec_count;

  const InfoElement* ie_otime_;
  const InfoElement* ie_value_;
  const InfoElement* ie_label_;

  MatchTemplate t;

public:
  TestObsReceiver()
    : pass_(true), 
      rec_count(0),
      ie_otime_(InfoModel::instance().lookupIE("observationTimeMilliseconds")),
      ie_value_(InfoModel::instance().lookupIE("observationValue")),
      ie_label_(InfoModel::instance().lookupIE("observationLabel")) {

    assert(ie_otime_ != 0);
    assert(ie_value_ != 0);
    assert(ie_label_ != 0);

    t.add(ie_otime_);
    t.add(ie_value_);
    t.add(ie_label_);
  }

  IETemplate* get_template() {
    return &t;
  }

  bool is_passing() const { 
    return pass_;
  }

  unsigned int get_rec_count() const {
    return rec_count;
  }

  void receiveRecord()  {
    rec_count++;

    uint64_t otime;
    uint64_t value;
    std::string label;

    if (getValue(ie_otime_, otime)
        && getValue(ie_value_, value)
        && getValue(ie_label_, label)) {
      TestObs o(otime, value, label);
      if (o_ != o)
        pass_ = false;
    } else
      pass_ = false;

    o_.incrementPattern();
  }
  
};


static bool file_exists(const std::string& name) {
   return std::ifstream(name);
}

static void write_file(const std::string& filename) {
  TestFlow flow;
  TestObs obs;
  Exporter *e = new FileWriter(filename, kTestDomain);

  assert(e != 0);

  std::cerr << "Writing" << std::endl;

  flow.prepareExport(*e);
  obs.prepareExport(*e);

  e->exportTemplatesForDomain();

  for (unsigned int i = 0 ; i < kTestCycleCount; i++) {
    for (unsigned int k = 0; k < kTestFlowPerSetCount; k++) {
      flow.do_export(*e);
      flow.incrementPattern();
    }

    for (unsigned int k = 0 ; k < kTestObsPerSetCount; k++) {
      obs.do_export(*e);
      obs.incrementPattern();
    }
  }

  e->flush();
  delete e;
}

static void read_file_with_record_interface(const std::string& filename) {
  Collector* c = new FileReader(filename);

  assert(c != 0);

  std::cerr << "Reading" << std::endl;

  TestFlowReceiver flow_receiver;
  c->registerReceiver(flow_receiver.get_template(), &flow_receiver);

  TestObsReceiver obs_receiver;
  c->registerReceiver(obs_receiver.get_template(), &obs_receiver);

  MBuf mbuf;
  while (c->receiveMessage(mbuf))
    mbuf.clear();

  delete c;
}

static void read_file_with_placement_interface(const std::string& filename) {
  class MyCallback : public PlacementCallback {
  public:
    MyCallback(DataSetDecoder& dsd)
    {
      PlacementTemplate* my_flow_template = new PlacementTemplate();

      my_flow_template->register_placement(
        InfoModel::instance().lookupIE("flowStartMilliseconds"),
        &flow_start_milliseconds);
      my_flow_template->register_placement(
        InfoModel::instance().lookupIE("flowEndMilliseconds"),
        &flow_end_milliseconds);
      my_flow_template->register_placement(
        InfoModel::instance().lookupIE("sourceIPv4Address"),
        &source_ip_v4_address);
      my_flow_template->register_placement(
        InfoModel::instance().lookupIE("destinationIPv4Address"),
        &destination_ip_v4_address);
      my_flow_template->register_placement(
        InfoModel::instance().lookupIE("sourceTransportPort"),
        &source_transport_port);
      my_flow_template->register_placement(
        InfoModel::instance().lookupIE("destinationTransportPort"),
        &destination_transport_port);
      my_flow_template->register_placement(
        InfoModel::instance().lookupIE("protocolIdentifier"),
        &protocol_identifier);
      my_flow_template->register_placement(
        InfoModel::instance().lookupIE("octetDeltaCount[4]"),
        &octet_delta_count);

      dsd.register_placement_template(my_flow_template, this);

      PlacementTemplate* my_obs_template = new PlacementTemplate();

      my_obs_template->register_placement(
         InfoModel::instance().lookupIE("observationTimeMilliseconds"),
         &observation_time_milliseconds);
      my_obs_template->register_placement(
         InfoModel::instance().lookupIE("observationValue"),
         &observation_value);
      my_obs_template->register_placement(
         InfoModel::instance().lookupIE("observationLabel"),
        &observation_label);

      dsd.register_placement_template(my_obs_template, this);
    }

    void start_placement(const PlacementTemplate* tmpl) {
    }

    void end_placement(const PlacementTemplate* tmpl) {
    }

  private:
    uint64_t flow_start_milliseconds;
    uint64_t flow_end_milliseconds;
    uint32_t source_ip_v4_address;
    uint32_t destination_ip_v4_address;
    uint16_t source_transport_port;
    uint16_t destination_transport_port;
    uint8_t  protocol_identifier;
    uint64_t octet_delta_count;

    uint64_t observation_time_milliseconds;
    uint64_t observation_value;
    BasicOctetArray observation_label;
  };

  DataSetDecoder dsd;
  IPFIXReader ir;
  MyCallback cb(dsd);

  ir.set_content_handler(&dsd);
  ir.set_error_handler(&dsd);

  int fd = open(filename.c_str(), O_RDONLY);
  if (fd >= 0) {
    FileInputSource is(fd);
    try {
      ir.parse(is);
    } catch (FormatError e) {
      std::cerr << "Format error: " << e.what() << std::endl;
    }
    (void) close(fd);
  }

}

int main(int argc, const char* argv[]) {
  InfoModel::instance().defaultIPFIX();
  TestFlow::addIEs();
  TestObs::addIEs();

  static const std::string filename = "loopfile";

  if (!file_exists(filename)) {
    write_file(filename);
  } else if (argc > 1) {
    if (strcmp(argv[1], "--record") == 0)
      read_file_with_record_interface(filename);
    else if (strcmp(argv[1], "--placement") == 0)
      read_file_with_placement_interface(filename);
  }
  return 0;
}
