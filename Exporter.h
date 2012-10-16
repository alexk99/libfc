/* Copyright (c) 2011-2012 ETH Zürich. All rights reserved.
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
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT 
 * HOLDERBE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY 
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 * @author Brian Trammell <trammell@tik.ee.ethz.ch>
 * 
 * Defines the abstract exporter interface.
 */

#ifndef IPFIX_EXPORTER_H // idem
#define IPFIX_EXPORTER_H // hack

#include <ctime>
#include <stdexcept>
#include "Session.h"
#include "Transcoder.h"
#include "OffsetCache.h"

namespace IPFIX {

/**
 * To send IPFIX Messages, client code should create an instance
 * of an Exporter subclass for the necessary transport, define Templates
 * by calling getTemplate(), using add() to add InfoElements to templates,
 * followed by activate() to activate each template for export, then use one
 * of the two data export interfaces below.
 *
 * This abstract class provides two ways of exporting data in IPFIX messages.
 * The main interface uses a record cursor and directly addresses InfoElements
 * within the export template. This interface provides for flexible encoding 
 * of data values. To use it, open a new record with beginRecord(), 
 * then write individual record values with one of the putValue() methods, 
 * and finish the record with exportRecord(). nformation 
 * Elements in the wire template not given values by putValue() will be 
 * exported as zeroes. Any variable-length Information Elements 
 * must have their lengths  reserved before any call to putValue() for a 
 * record: use reserveVarlen() for each infomation element followed by 
 * commitVarlen() to calculate the record length.
 *
 * The second interface is designed for speed and based on C-structure 
 * transcoding. To use it, client code should place the data to be exported 
 * in a C structure, create a StructTemplate describing that structure, 
 * then use exportStruct() to export the record according to the 
 * current wire template. Structures to be exported via this interface 
 * must contain only fixed-length primitive data members or variable-length 
 * data members represented by an IPFIX::VarlenField structure. Information 
 * Elements in the wire template not represented in the structure will be 
 * exported as zeroes. 
 *
 * flush() can be called to explicitly end a message.
 *
 * Template management is achieved through getTemplate() (which will
 * create a new template for export if it doesn't exist yet) and
 * exportTemplatesForDomain().
 */
class Exporter {
  
public:

  /**
   * Change the active observation domain for the exporter.
   *
   * @param domain new observation domain ID
   */
  void setDomain(uint32_t domain);

  /**
   * Change the active template for the exporter. 
   *
   * @param tid new template ID
   */
  void setTemplate(uint16_t tid);
  
  /**
   * Get the WireTemplate for a given template ID in the current 
   * observation domain. Creates a new inactive template if no
   * template has yet been created for this ID. Template ID assignment
   * may be done statically by the application, or dynamically using
   * the TemplateRegistry class.
   *
   * @param tid template ID to get
   * @return pointer to template for given ID
   */
  WireTemplate *getTemplate(uint16_t tid) { 
    return session_.getTemplate(domain_, tid); 
  }
  
  /**
   * Export all active templates for the current observation domain.
   */
  void exportTemplatesForDomain();
  
  /**
   * Export a record stored in a C structure described by a given structure 
   * template, using the current wire template.
   *
   * @param struct_tmpl template describing struct_cp
   * @param struct_cp pointer to structure to export
   */
  void exportStruct(const StructTemplate &struct_tmpl, uint8_t* struct_cp);
  
  /**
   * Begin a new record for export with the current wire template.
   * Initializes all Information Elements in the export record to zero.
   * May cause export of a message if there is not space for the new record
   * in the current message.
   */
  
  void beginRecord();

  /**
   * Export the currently open record cursor.
   */
   
  void exportRecord() { endRecord(true); }

  /**
   * Roll back the currently open record cursor.
   */
   
  void rollbackRecord() { endRecord(false); }
  
  /**
   * Reserve space in the current record for a variable-length Information 
   * Element; a subsequent call to putValue() within the same record for 
   * this Information Element must have the same size. Reservations of 
   * lengths for fixed-length Information Elements are no-ops. After
   * reserving lengths, commitVarlen() must be called to calculate the
   * total record length.
   *
   * @param ie information element to reserve length for
   * @param len length to reserve
   */
  
   void reserveVarlen(const InfoElement *ie, size_t len);
  
  /**
   * Commit previous reservations of variable-length Information Elements
   * and caculate the record. Call after all reserveVarlen() calls and
   * before any putValue calls().
   * May cause export of a message if there is not space for the new record
   * in the current message.
   */
  
   void commitVarlen();
  
  /**
   * Put a value at the given Information Element in the current record.
   * Performs no operation if the given Information Element does not exist
   * in the current wire template. Overwrites previously put values for
   * Information Elements which are fixed length in the current wire template.
   *
   * Information Elements must be put into the record in the order in
   * which they appear in the WireTemplate. (The present implementation 
   * will not fail on out-of-order puts, but future implementations may.)
   *
   * For variable-length IEs, client code is therefore strongly encouraged 
   * to use reserveValueLength() directly after beginRecord(), if possible. 
   * 
   * @param ie pointer to Information Element describing the value.
   * @param vp pointer to the value to copy into the message. This value must
   *           be in host byte order, and of appropriate type for the given
   *           Information Element. No type checks are performed.
   * @param len Length of the value in vp.
   * @return true if the value was put, or if the value was ignored because
   *         the current wire template does not contain the given IE.
   *         If false, there was not enough room to put the value, 
   *         and the record was rolled back.
   */
  
    bool putValue(const InfoElement* ie, const void* vp, size_t len);

  /**
   * Put a value at the given Information Element 
   * in the current record.
   */
    template <typename T> 
    bool putValue(const InfoElement* ie, const T& v) {
        return putValue(ie, &v, sizeof(v));
    }

  /**
   * Put a string at the given Information Element 
   * in the current record. The string will be exported with its
   * natural length if the corresponding IE in the current wire
   * template is variable length; otherwise, it will be right-truncated
   * or right-padded.
   */

    bool putValue(const InfoElement* ie, const std::string& v) {
        return putValue(ie, v.c_str(), v.size());
    }

  /**
   * Flush the current message with the given export time
   *
   * @param export time export time in epoch seconds
   */

  void flush(time_t export_time);

  /**
   * Flush the current message with the export time
   *
   * @param export time export time in epoch seconds
   */  

  void flush() { flush(time(NULL)); }
  
  // FIXME fix signed/unsigned issues in export time throughout libfc

  // FIXME add a way to withdraw a template


  /**
   * Call to put this Exporter into fast-flush mode. In fast flush mode,
   * each record will go into its own IPFIX message. Use to avoid buffering
   * latency, or to debug client code that cannot flush on shutdown properly.
   */
   void setFastFlush() { fast_flush_ = true; }

  /**
   * Exporter virtual destructor
   */

  virtual ~Exporter();

protected:
  /**
   * Create a new Exporter.
   *
   * Called by subclasses to initialize Exporter internal
   * structures.
   *
   * @param domain initial observation domain; 
   *               can be changed after creation with setDomain()
   * @param mtu maximum message size
   */
  Exporter(uint32_t domain, size_t mtu);
  
  void endRecord(bool do_export); 
  
  /**
   * Low-level interface to export interface; overridden by subclasses
   *
   * @param base pointer to buffer to send
   * @param len length of buffer to send
   */  
  virtual void _sendMessage(uint8_t *base, size_t len) = 0;

private:
  // make me uncopyable
  Exporter();
  Exporter(Exporter& rhs);
  Exporter& operator=(Exporter& rhs);

  void checkRecordOverflow(size_t reclen);

  void endSet() { xcoder_.encodeSetEnd(); set_active_ = false; }
  void ensureSet();
  void ensureTemplateSet();
  void startMessage();
  
  bool msgEmpty() { return !(drec_count_ || trec_count_); }
  
  // Low-level storage
  // storage for message buffer
  uint8_t*                  buf_;
  // transcoder (handles low-level IPFIX formatting)
  Transcoder                xcoder_;
  // Maximum message size
  size_t                    mtu_;
  // Fast flush mode flag
  bool                      fast_flush_;
  
  // Message export state
  // Session for storing IPFIX state
  Session                   session_;
  // Current domain for export
  uint32_t                  domain_;
  // current Set ID for export
  uint16_t                  set_id_;
  // TRUE if there is an active set
  bool                      set_active_;
  // Wire template describing the set
  WireTemplate*             tmpl_;

  // number of data records written since flush
  unsigned int              drec_count_;
  // number of template records written since flush
  unsigned int              trec_count_;

  // TRUE if there is an active record
  bool                      rec_active_;
  // TRUE if record length reserved
  bool                      rec_will_fit_;
  // Export cursor state
  ExporterOffsetCache       oc_;
};

}

#endif
