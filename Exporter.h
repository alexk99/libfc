/**
 * @file
 * @author Brian Trammell <trammell@tik.ee.ethz.ch>
 *
 * @section DESCRIPTION
 * 
 * Defines the abstract exporter interface.
 *
 * To send IPFIX Messages, client code should create an instance
 * of an Exporter subclass for the necessary transport, set the
 * observation domain via setDomain() and the export template via
 * setTemplate(), and call exportRecord() to send each record.
 *
 * flush() can be called to explicitly end a message.
 *
 * Template management is achieved through getTemplate() (which will
 * create a new template for export if it doesn't exist yet) and
 * exportTemplatesForDomain().
 */

#ifndef IPFIX_EXPORTER_H // idem
#define IPFIX_EXPORTER_H // hack

#include <ctime>
#include <stdexcept>
#include "Session.h"
#include "Transcoder.h"

namespace IPFIX {

class MTUError : public std::runtime_error {
public:
  explicit MTUError(const std::string& what_arg): 
    std::runtime_error(what_arg) {}
};
  
class Exporter {
  
public:

  /**
   * Create a new Exporter for a given information model,
   * inital observation domain, and maximum message size.
   *
   * Called by subclasses to initialize Exporter internal
   * structures.
   *
   */
  Exporter(const InfoModel* model, uint32_t domain, size_t mtu);
  virtual ~Exporter();
  
  void setDomain(uint32_t domain);
  void setTemplate(uint16_t tid);
  WireTemplate *getTemplate(uint16_t tid) { 
    return session_.getTemplate(domain_, tid); 
  }
  
  void exportTemplatesForDomain();
  
  void exportRecord(const StructTemplate &struct_tmpl, void *struct_vp);
  void flush(time_t export_time);
  void flush() { flush(time(NULL)); }

protected:
  virtual void _sendMessage(uint8_t *base, size_t len) = 0;

private:
  // make me uncopyable
  Exporter();
  Exporter(Exporter& rhs);
  Exporter& operator=(Exporter& rhs);

  void endSet() { xcoder_.encodeSetEnd(); set_active_ = false; }
  void ensureSet();
  void ensureTemplateSet();
  void startMessage();
  void endMessage(time_t export_time);
  
  
  uint8_t*                  buf_;
  Transcoder                xcoder_;
  uint16_t                  set_id_;
  bool                      msg_empty_;
  bool                      set_active_;
  Session                   session_;
  WireTemplate*             tmpl_;
  uint32_t                  domain_;
  size_t                    mtu_;
};

}

#endif