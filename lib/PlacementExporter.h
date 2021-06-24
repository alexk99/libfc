/* Hi Emacs, please use -*- mode: C++; -*- */
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

/**
 * @file
 * @author Stephan Neuhaus <neuhaust@tik.ee.ethz.ch>
 */

#ifndef _libfc_PLACEMENTEXPORTER_H_
#define _libfc_PLACEMENTEXPORTER_H_

#include <cstdint>
#include <list>
#include <set>
#include <vector>

#include <sys/uio.h>

#if defined(_libfc_HAVE_LOG4CPLUS_)
#include <log4cplus/logger.h>
#endif /* defined(_libfc_HAVE_LOG4CPLUS_) */

#include "Constants.h"
#include "ExportDestination.h"
#include "PlacementTemplate.h"
#include <rte_byteorder.h>

#ifndef atomic_inc_uint
#define	atomic_inc_uint(x)	__sync_fetch_and_add(x, 1)
#endif

class EncodePlan;

namespace libfc {

struct template_plan {
	PlacementTemplate* tpl;
	EncodePlan* plan;
	uint16_t tpl_id;
};

#define IPFIX_MAX_TPLS 4
#define FLOWSET_HDR_LEN 4
#define FLOWSET_VERSION 2

#ifdef LFC_DEBUG_PRINTF
#define libfc_printf(...) printf(__VA_ARGS__)
#else
#define libfc_printf(...)
#endif

class PlacementExporter {
private:	
	PlacementTemplate* current_tpl;
	EncodePlan* current_plan;

    /** Templates that need to go into this message's template record. */
	struct template_plan templates[IPFIX_MAX_TPLS];
	uint8_t n_templates;

    /** Most recently assigned template id. */
	uint16_t current_tpl_id;

    /** Sequence number for messages; see RFC 5101. */
	uint32_t* sequence_number_ptr;

    /** Observation domain for messages; see RFC 5101.
     *
     * For the moment, we support only one observation domain. This
     * may change in the future. */
    uint32_t observation_domain;

    /** Number of octets in this message so far. This includes message
     * and set headers, template sets and data sets. */
	uint16_t message_len;
	uint8_t* message_len_addr;

	uint16_t flowset_len;
	uint8_t* flowset_hdr_addr;

	bool template_flowset_closed;

	/* message buffer */
	uint8_t* buf;
	uint8_t* buf_pos;
	uint32_t buf_size;
	uint32_t buf_bytes_left;	

	struct template_plan*
	find_template(const PlacementTemplate* tpl);

	void
	fini(void);			

	void
	start_flowset(void);
		
	void 
	finish_flowset(void);

	int
	write_templates(void);

	void
	finish_message(void);
	
public:
	PlacementExporter(uint32_t _observation_domain, uint8_t* msg_buf,
		uint32_t msg_buf_size, uint32_t* _sequence_number_ptr);

	~PlacementExporter();
	
	void
	reset(void);
	
	void
	place_values(PlacementTemplate* tpl, bool _write_templates);
		
	int
	add_template(PlacementTemplate* tpl, uint16_t template_id);		
		
	int
	start_message(time_t now, bool inc_sequence_number);
		
	int
	complete_message(void);
	
	void
	set_buf(uint8_t* _buf, uint32_t _buf_size);
};

} // namespace libfc

#endif // _libfc_PLACEMENTEXPORTER_H_
