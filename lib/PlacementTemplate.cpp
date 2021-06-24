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
#include <climits>

#include <arpa/inet.h>
#include <rte_byteorder.h>

#if defined(_libfc_HAVE_LOG4CPLUS_)
#  include <log4cplus/loggingmacros.h>
#else
#  define LOG4CPLUS_TRACE(logger, expr)
#endif /* defined(_libfc_HAVE_LOG4CPLUS_) */

#include "BasicOctetArray.h"
#include "PlacementTemplate.h"

namespace libfc {

  class PlacementTemplate::PlacementInfo {
  public:
    PlacementInfo(const InfoElement* ie, void* address, size_t size_on_wire);

    /** Information element.
     *
     * This is used to find out the type of varlen-encoded IEs
     */
    const InfoElement* ie;

    /** Address where to write/read values from/to. */
    void* address;
    
    /** Size of InfoElement on the wire. This is useful only when
     * exporting. */
    size_t size_on_wire;
  };

  PlacementTemplate::PlacementInfo::PlacementInfo(const InfoElement* _ie,
                                                  void* _address,
                                                  size_t _size_on_wire) 
    : ie(_ie), address(_address), size_on_wire(_size_on_wire) {
  }

  PlacementTemplate::PlacementTemplate() 
    : buf(0), 
      size(0),
      fixlen_data_record_size(0),
      template_id(0)
#if defined(_libfc_HAVE_LOG4CPLUS_)
    , logger(log4cplus::Logger::getInstance(LOG4CPLUS_TEXT("PlacementTemplate")))
#endif /* defined(_libfc_HAVE_LOG4CPLUS_) */
  {
  }

  PlacementTemplate::~PlacementTemplate() {
		if (placements.size() > 0) {
			for (auto i = placements.begin(); i != placements.end(); ++i)
				delete i->second;	
		}
		
    delete[] buf;
  }

  bool PlacementTemplate::register_placement(const InfoElement* ie,
                                             void* p, size_t size) {
	assert(ie != NULL);
    if (size == 0)
      size = ie->len();
    placements[ie] = new PlacementInfo(ie, p, size);
    ies.push_back(ie);

    if (size == kIpfixVarlen)
      varlen_ies.push_back(placements[ie]);
    else
      fixlen_data_record_size += size;

    return true;
  }

  bool PlacementTemplate::lookup_placement(const InfoElement* ie,
                                           void** p, size_t* size) const {
    LOG4CPLUS_TRACE(logger, "ENTER lookup_placement");
    for (auto i = placements.begin(); i != placements.end(); ++i) {
      if (i->first->matches(*ie)) {
        *p = i->second->address;
        if (size != 0)
          *size = i->second->size_on_wire;
        return true;
      }
    }

    *p = 0;
    return false;
  }

  unsigned int PlacementTemplate::is_match(
      const IETemplate* t,
      std::set<const InfoElement*>* unmatched) const {
    LOG4CPLUS_TRACE(logger, "ENTER is_match");
    
    bool found = true;

    for (auto i = placements.begin(); i != placements.end(); ++i) {
      LOG4CPLUS_TRACE(logger, "  looking up IE " << i->first->toIESpec());
      if (!t->contains(i->first)) {
        LOG4CPLUS_TRACE(logger, "    not found -> false");
        found = false;
        break;
      }
    }

    if (found) {
      LOG4CPLUS_TRACE(logger, "  all found -> return " << placements.size());
      assert(placements.size() <= UINT_MAX);

      if (unmatched != 0) {
        unmatched->clear();

        for (auto i = t->begin(); i != t->end(); ++i) {
          bool found = false;
          for (auto k = placements.begin(); k != placements.end(); ++k) {
            if (k->first->matches(*(*i))) {
              found = true;
              break;
            }
          }
          if (!found)
            unmatched->insert(*i);
        }
      }

      return static_cast<unsigned int>(placements.size());
    } else
      return 0;
  }

/*
 * Returns: 
 *	> 0 - ok, size of template record
 *  <0 - error
 */
int
PlacementTemplate::wire_template(uint16_t _template_id, uint8_t* _buf, uint32_t _buf_size) const 
{ 
	LOG4CPLUS_TRACE(logger, "computing wire template, id=" << _template_id);
      assert(_template_id != 0);
	
      /* Templates start with a 2-byte template ID and a 2-byte field
       * count. */
      size =  sizeof(uint16_t) + sizeof(uint16_t);
      uint16_t n_fields = 0;

      for (auto i = placements.begin(); i != placements.end(); ++i) {
        /* A template record is 2 bytes for the IE id, 2 bytes for
         * the field length and a potential 4 more bytes for the
         * private enterprise number, if there is one. */
		size += sizeof(uint16_t) + sizeof(uint16_t)
          + (i->first->pen() == 0 ? 0 : sizeof(uint32_t));
        n_fields++;
      }

	if (size > _buf_size)
		/* not enough space */
		return -1;

	/* template ID */
	template_id = _template_id;
	_template_id = rte_cpu_to_be_16(_template_id);
	memcpy(_buf, &_template_id, sizeof(_template_id));
	_buf += sizeof(_template_id);

	/* field count */
	n_fields = rte_cpu_to_be_16(n_fields);
	memcpy(_buf, &n_fields, sizeof(n_fields));
	_buf += sizeof(n_fields);

      
	/* Use IES, not PLACEMENTS for iteration, because now, 
	 * sequence matters. */
      for (auto i = ies.begin(); i != ies.end(); ++i) {
		uint32_t ie_pen = rte_cpu_to_be_32((*i)->pen());
		uint16_t ie_id = rte_cpu_to_be_16((*i)->number() | (ie_pen == 0 ? 0 : (1 << 15)));
		uint16_t ie_len = rte_cpu_to_be_16((*i)->len());
		memcpy(_buf, &ie_id, sizeof(ie_id)); 
		_buf += sizeof(ie_id);
		memcpy(_buf, &ie_len, sizeof(ie_len)); 
		_buf += sizeof(ie_len);

        if (ie_pen != 0) {
			memcpy(_buf, &ie_pen, sizeof(ie_pen));
			_buf += sizeof(ie_pen);
        }
      }

	return size;
}

/*
 *
 */
  size_t PlacementTemplate::data_record_size() const {
    size_t ret = fixlen_data_record_size;

    if (varlen_ies.size() != 0) {
      for (auto i = varlen_ies.begin(); i != varlen_ies.end(); ++i) {
        uint16_t varlen_len
          = reinterpret_cast<BasicOctetArray*>((*i)->address)->get_length();
        ret += varlen_len + (varlen_len < 255 ? 1 : 3);
      }
    }
    return ret;
  }

  uint16_t PlacementTemplate::get_template_id() const {
    return template_id;
  }

  std::list<const InfoElement*>::const_iterator 
  PlacementTemplate::begin() const {
    return ies.begin();
  }

  std::list<const InfoElement*>::const_iterator 
  PlacementTemplate::end() const {
    return ies.end();
  }

} // namespace libfc
