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
#include <algorithm>
#include <climits>
#include <ctime>
#include <cstdarg>
#include <sstream>

#include <unistd.h>
// todo use rte_cpu_to_be 
#include <arpa/inet.h>

#if defined(_libfc_HAVE_LOG4CPLUS_)
#  include <log4cplus/loggingmacros.h>
#else
#define LOG4CPLUS_TRACE(...)
#endif /* defined(_libfc_HAVE_LOG4CPLUS_) */

#include "ipfix_endian.h"

#include "BasicOctetArray.h"
#include "PlacementExporter.h"

#include "exceptions/ExportError.h"


/** Encode plans describe how a data record is to be encoded.
 *
 * Decoding a data record means determining, for each data field, 
 *
 *   - if the data's endianness must be converted;
 *   - if the data needs to be transformed in any other way (for
 *     example, boolean values are encoded with 1 meaning true and 2
 *     meaning false(!!), or reduced-length encoding of floating-point
 *     values means that doubles are really transferred as floats); and
 *   - for variable-length data, what the length of the encoded value
 *     is.
 *
 * See also the documentation for DecodePlan in DataSetDecoder.cpp
 */
class EncodePlan {
public:
  /** Creates an encoding plan from a placement template.
   *
   * @param placement_template a placement template from which we
   *   encode a data record.
   */
  EncodePlan(const libfc::PlacementTemplate* placementTemplate);

  /** Executes this plan.
   *
   * @param buf the buffer where to store the encoded values
   * @param offset the offset at which to store the values
   * @param length the total length of the buffer
   *
   * @return the number of encoded octets
   */
  uint16_t execute(uint8_t* buf, uint16_t offset, uint16_t length);
  
private:
  struct Decision {
    /** The decision type. */
    enum decision_type_t {
      /** Value for an uninitialised decision type. */
      encode_none,

      /** Encode a boolean.  I'm repeating here the comment I made in
       * the corresponding declaration for transfer_boolean in
       * DataSetDecoder.cpp, because it still gets my blood up:
       *
       * Someone found it amusing in RFC 2579 to encode the boolean
       * values true and false as 1 and 2, respectively [sic!].  And
       * someone else found it amusing to standardise this behaviour
       * in RFC 5101 too.  This is of course wrong, since it disallows
       * entirely sensible operations like `plus' for "or", `times'
       * for "and" and `less than' for implication (which is what you
       * get when you make false less than true).
       *
       * This is why we can't subsume the encoding of booleans (which
       * are fixlen-encoded values of length 1) under
       * encode_basic_no_endianness below. */
      encode_boolean,

      /** Encode a basic type (fixlen) with no endianness conversion. */
      encode_fixlen,

      /** Encode a basic type (fixlen) with endianness conversion. */
      encode_fixlen_endianness,

      /** Encode a BasicOctetArray as fixlen. */
      encode_fixlen_octets,

      /** Encode a BasicOctetArray as varlen. Varlen encoding is
       * supported only for BasicOctetArray and derived classes.  In
       * all other instances, I'll do what Brian Trammell recommended
       * I do and tell the user to eff off. */
      encode_varlen,

      /** Encode double as float with endianness conversion. */
      encode_double_as_float_endianness,

      /** Encode double as float, no endianness conversion. */
      encode_double_as_float,
    } type;

    /** Address where original value is to be found. */
    const void* address;

    /** Size of original (unencoded) data. 
     *
     * If type is encode_varlen or encode_double_as_float or
     * encode_fixlen_octets, this field is implied and may not contain
     * a valid value.
     */
    size_t unencoded_length;

    /** Requested size of encoded data. 
     *
     * If type is encode_varlen or encode_double_as_float, this field
     * is implied and may not contain a valid value.
     */
    size_t encoded_length;

    /** Creates a printable version of this encoding decision. 
     *
     * @return a printable version of this encoding decision
     */
    std::string to_string() const;
  };

  std::vector<Decision> plan;

#  if defined(_libfc_HAVE_LOG4CPLUS_)
  log4cplus::Logger logger;
#  endif /* defined(_libfc_HAVE_LOG4CPLUS_) */
};


static void report_error(const char* message, ...) {
  static const size_t buf_size = 10240;
  static char buf[buf_size];
  va_list args;
  
  va_start(args, message);
  int nchars = vsnprintf(buf, buf_size, message, args);
  va_end(args);

  if (nchars < 0)
    strcpy(buf, "Error while formatting error message");
  else if (static_cast<unsigned int>(nchars) > buf_size - 1 - 3) {
    buf[buf_size - 4] = '.';
    buf[buf_size - 3] = '.';
    buf[buf_size - 2] = '.';
    buf[buf_size - 1] = '\0';   // Shouldn't be necessary
  }

  throw libfc::ExportError(buf);
}

/* See DataSetDecoder::DecodePlan::DecodePlan. */
EncodePlan::EncodePlan(const libfc::PlacementTemplate* placement_template)
#if defined(_libfc_HAVE_LOG4CPLUS_)
  : logger(log4cplus::Logger::getInstance(LOG4CPLUS_TEXT("EncodePlan")))
#endif /* defined(_libfc_HAVE_LOG4CPLUS_) */
 {
#if defined(IPFIX_BIG_ENDIAN)
  Decision::decision_type_t encode_fixlen_maybe_endianness
    = Decision::encode_fixlen;
  Decision::decision_type_t encode_double_as_float_maybe_endianness
    = Decision::encode_double_as_float;
#elif defined(IPFIX_LITTLE_ENDIAN)
  Decision::decision_type_t encode_fixlen_maybe_endianness
    = Decision::encode_fixlen_endianness;
  Decision::decision_type_t encode_float_into_double_maybe_endianness
    = Decision::encode_double_as_float_endianness;
#else
#  error libfc does not compile on weird-endian machines.
#endif

  LOG4CPLUS_TRACE(logger, "Yay EncodePlan");

  for (auto ie = placement_template->begin();
       ie != placement_template->end();
       ++ie) {
    assert(*ie != 0);
    assert((*ie)->ietype() != 0);

    Decision d;
    void* location;
    size_t size;

    /* Either g++ is too stupid to figure out that the relevant fields
     * will all be set in the various cases below (not even with -O3),
     * or I really have forgotten to set them.  Unfortunately, all the
     * error message says is that "warning:
     * ‘d.EncodePlan::Decision::xxx’ may be used uninitialized in this
     * function", and then pointing to the *declaration* of d, and not
     * at the places where it thinks that the variable might be used
     * uninitialised.  I'm therefore forced to initialise (possibly
     * redundantly) the members of the struct, just to shut the
     * compiler up. Not helpful. */
    d.type = Decision::encode_none;
    d.unencoded_length = 0;
    d.encoded_length = 0;

    /* The IE *must* be present in the placement template. If not,
     * there is something very wrong in the PlacementTemplate
     * implementation.  Weird construction is to avoid call to
     * lookup_placement() to be thrown out when compiling with
     * -DNDEBUG. */
    bool ie_present 
      = placement_template->lookup_placement(*ie, &location, &size);
    assert(ie_present);

    d.address = location;

    switch ((*ie)->ietype()->number()) {
    case libfc::IEType::kOctetArray: 
      if (size == libfc::kIpfixVarlen) {
        d.type = Decision::encode_varlen;
      } else {
        d.type = Decision::encode_fixlen_octets;
        d.encoded_length = size;
      }
      break;

    case libfc::IEType::kUnsigned8:
      assert(size <= sizeof(uint8_t));

      d.type = Decision::encode_fixlen;
      d.unencoded_length = sizeof(uint8_t);
      d.encoded_length = size;
      break;

    case libfc::IEType::kUnsigned16:
      assert(size <= sizeof(uint16_t));

      d.type = encode_fixlen_maybe_endianness;
      d.unencoded_length = sizeof(uint16_t);
      d.encoded_length = size;
      break;

    case libfc::IEType::kUnsigned32:
      assert(size <= sizeof(uint32_t));

      d.type = encode_fixlen_maybe_endianness;
      d.unencoded_length = sizeof(uint32_t);
      d.encoded_length = size;
      break;

    case libfc::IEType::kUnsigned64:
      assert(size <= sizeof(uint64_t));

      d.type = encode_fixlen_maybe_endianness;
      d.unencoded_length = sizeof(uint64_t);
      d.encoded_length = size;
      break;

    case libfc::IEType::kSigned8:
      assert(size <= sizeof(int8_t));

      d.type = encode_fixlen_maybe_endianness;
      d.unencoded_length = sizeof(int8_t);
      d.encoded_length = size;
      break;

    case libfc::IEType::kSigned16:
      assert(size <= sizeof(int16_t));

      d.type = encode_fixlen_maybe_endianness;
      d.unencoded_length = sizeof(int16_t);
      d.encoded_length = size;
      break;

    case libfc::IEType::kSigned32:
      assert(size <= sizeof(int32_t));

      d.type = encode_fixlen_maybe_endianness;
      d.unencoded_length = sizeof(int32_t);
      d.encoded_length = size;
      break;

    case libfc::IEType::kSigned64:
      assert(size <= sizeof(int64_t));

      d.type = encode_fixlen_maybe_endianness;
      d.unencoded_length = sizeof(int64_t);
      d.encoded_length = size;
      break;

    case libfc::IEType::kFloat32:
      /* Can't use reduced-length encoding on float; see RFC 5101,
       * Chapter 6, Verse 2. */
      assert(size == sizeof(uint32_t));

      d.type = encode_fixlen_maybe_endianness;
      d.unencoded_length = sizeof(uint32_t);
      d.encoded_length = sizeof(uint32_t);
      break;

    case libfc::IEType::kFloat64:
      assert(size == sizeof(uint32_t)
             || size == sizeof(uint64_t));

      d.unencoded_length = sizeof(uint64_t);
      d.encoded_length = size;
      if (d.unencoded_length == sizeof(uint32_t))
        d.type = encode_float_into_double_maybe_endianness;
      else
        d.type = encode_fixlen_maybe_endianness;
      break;

    case libfc::IEType::kBoolean:
      assert(size == sizeof(uint8_t));

      d.type = Decision::encode_boolean;
      d.unencoded_length = size;
      d.encoded_length = size;
      break;

    case libfc::IEType::kMacAddress:
      /* RFC 5101 says to treat MAC addresses as 6-byte integers,
       * but Brian Trammell says that this is wrong and that the
       * RFC will be changed.  If for some reason this does not
       * come about, replace "encode_fixlen" with
       * "encode_fixlen_maybe_endianness". */
      assert(size == 6*sizeof(uint8_t));
             
      d.type = Decision::encode_fixlen;
      d.unencoded_length = size;
      d.encoded_length = size;
      break;
        
    case libfc::IEType::kString:
      if (size == libfc::kIpfixVarlen) {
        d.type = Decision::encode_varlen;
      } else {
        d.type = Decision::encode_fixlen_octets;
        d.encoded_length = size;
      }
      break;

    case libfc::IEType::kDateTimeSeconds:
      /* Must be encoded as a "32-bit integer"; see RFC 5101, Chapter
       * 6, Verse 1.7.
       *
       * The standard doesn't say whether the integer in question is
       * signed or unsigned, but since there is additional information
       * saying that "[t]he 32-bit integer allows the time encoding up
       * to 136 years", this makes sense only if the integer in
       * question is unsigned (signed integers give 68 years, in
       * either direction from the epoch). */
      assert(size == sizeof(uint32_t));

      d.type = encode_fixlen_maybe_endianness;
      d.unencoded_length = size;
      d.encoded_length = size;
      break;
        
    case libfc::IEType::kDateTimeMilliseconds:
      /* Must be encoded as a "64-bit integer"; see RFC 5101, Chapter
       * 6, Verse 1.8.
       *
       * The standard doesn't say whether the integer in question is
       * signed or unsigned, but in analogy with dateTimeSeconds, we
       * will assume the unsigned variant. */
      assert(size == sizeof(uint64_t));

      d.type = encode_fixlen_maybe_endianness;
      d.unencoded_length = size;
      d.encoded_length = size;
      break;
        
    case libfc::IEType::kDateTimeMicroseconds:
      /* Must be encoded as a "64-bit integer"; see RFC 5101, Chapter
       * 6, Verse 1.9. See dateTimeMilliseconds above. */
      assert(size == sizeof(uint64_t));

      d.type = encode_fixlen_maybe_endianness;
      d.unencoded_length = size;
      d.encoded_length = size;
      break;
        
    case libfc::IEType::kDateTimeNanoseconds:
      /* Must be encoded as a "64-bit integer"; see RFC 5101, Chapter
       * 6, Verse 1.10.  See dateTimeMicroseconds above. */
      assert(size == sizeof(uint64_t));

      d.type = encode_fixlen_maybe_endianness;
      d.unencoded_length = size;
      d.encoded_length = size;
      break;
                
    case libfc::IEType::kIpv4Address:
      /* RFC 5101 says to treat all addresses as integers. This
       * would mean endianness conversion for all of these address
       * types, including MAC addresses and IPv6 addresses. But the
       * only reasonable address type with endianness conversion is
       * the IPv4 address.  If for some reason this is not correct
       * replace "encode_fixlen_maybe_endianness" with
       * "encode_fixlen".
       *
       * Also, treating addresses as integers would subject them to
       * reduced-length encoding, a concept that is quite bizarre
       * since you can't do arithmetic on addresses.  We will
       * therefore not accept reduced-length encoding on addresses.
       */
      assert(size == sizeof(uint32_t));

      d.type = encode_fixlen_maybe_endianness;
      d.unencoded_length = size;
      d.encoded_length = size;
      break;
        
    case libfc::IEType::kIpv6Address:
      /* See comment on kIpv4Address. */
      assert(size == 16*sizeof(uint8_t));

			// d.type = encode_fixlen_maybe_endianness;
			d.type = Decision::encode_fixlen;
      d.unencoded_length = size;
      d.encoded_length = size;
      break;
        
    default: 
      report_error("Unknown IE type");
      break;
    }
    
    if ((d.type == Decision::encode_fixlen 
         || d.type == Decision::encode_fixlen_endianness)
        && d.encoded_length > d.unencoded_length) {
      /* Don't eliminate the temporary ie_spec.  If you do, the
       * temporary object created by toIESpec() may be deleted before
       * report_error is called, invalidating c_str(). */
      std::string ie_spec = (*ie)->toIESpec();
      report_error("IE %s encoded length %zu greater than native size %zu",
                   ie_spec.c_str(), d.encoded_length,
                   d.unencoded_length);
    }
    LOG4CPLUS_TRACE(logger, "encoding decision " << d.to_string());

    plan.push_back(d);
  }
}

std::string EncodePlan::Decision::to_string() const {
  std::stringstream sstr;

  sstr << "[";

  switch (type) {
  case encode_none: sstr << "encode_none"; break;
  case encode_boolean: sstr << "encode_boolean"; break;
  case encode_fixlen: sstr << "encode_fixlen"; break;
  case encode_fixlen_endianness: sstr << "encode_fixlen_endianness"; break;
  case encode_fixlen_octets: sstr << "encode_fixlen_octets"; break;
  case encode_varlen: sstr << "encode_varlen"; break;
  case encode_double_as_float_endianness:
    sstr << "encode_double_as_float_endianness";
    break;
  case encode_double_as_float:
    sstr << "encode_double_as_float";
    break;
  }

  sstr << "@" << address << "[" << encoded_length << "]";
  return sstr.str();
}

uint16_t EncodePlan::execute(uint8_t* buf, uint16_t offset,
                             uint16_t length) {
  uint16_t ret = 0;

  /* Make sure that there is space for at least one more octet. */
  assert(offset < length);

  for (auto i = plan.begin(); i != plan.end(); ++i) {
    /** An RFC 2579-encoded truth value.
     *
     * Really, look it up in http://tools.ietf.org/html/rfc2579 :
     *
     * TruthValue ::= TEXTUAL-CONVENTION
     *     STATUS       current
     *     DESCRIPTION
     *             "Represents a boolean value."
     *     SYNTAX       INTEGER { true(1), false(2) }
     *
     * Seriously, Internet? */
    static const uint8_t rfc2579_madness[] = { 2, 1 };

    uint16_t bytes_copied = 0;

    switch (i->type) {
    case Decision::encode_none:
      assert (0 == "being asked to encode_none");
      break;

    case Decision::encode_boolean:
      LOG4CPLUS_TRACE(logger, "encode_boolean");
      {
        const bool* p = static_cast<const bool*>(i->address);
        assert(offset + 1 <= length);
        buf[offset] = rfc2579_madness[static_cast<int>(*p != 0)];
        bytes_copied = 1;
      }
      break;

    case Decision::encode_fixlen:
      assert(offset + i->encoded_length <= length);
      memcpy(buf + offset,
             static_cast<const uint8_t*>(i->address) + i->unencoded_length - i->encoded_length,
             i->encoded_length);
      ret += i->encoded_length;
      offset += i->encoded_length;
      break;

    case Decision::encode_fixlen_endianness:
      {
        const uint8_t* src = static_cast<const uint8_t*>(i->address);
        uint8_t* dst = buf + offset + i->encoded_length - 1;

        assert(offset + i->encoded_length <= length);

        while (dst >= buf + offset)
          *dst-- = *src++;

        bytes_copied = i->encoded_length;
      }
      break;

    case Decision::encode_fixlen_octets:
      {
        const libfc::BasicOctetArray* src
          = static_cast<const libfc::BasicOctetArray*>(i->address);
        const size_t bytes_to_copy
          = std::min(src->get_length(), i->encoded_length);

        assert(offset + i->encoded_length <= length);

        memcpy(buf + offset, src->get_buf(), bytes_to_copy);
        memset(buf + offset + bytes_to_copy, '\0',
               i->encoded_length - bytes_to_copy);

        bytes_copied = i->encoded_length;
      }
      break;

    case Decision::encode_varlen:
      /* There seems to be no good way to do varlen encoding without
       * a lot of branches, either implicit or explicit.  It would
       * IMHO have been better if octetArray or string fields simply
       * had a 2-octet length field and be done with it. 
       *
       * Also, don't be worried about the many calls to get_length()
       * below; this is a const member function which allows the
       * compiler to optimise away all but one call to it. ---neuhaus */
      {
        const libfc::BasicOctetArray* src
          = static_cast<const libfc::BasicOctetArray*>(i->address);
        LOG4CPLUS_TRACE(logger,
                        "  encoding varlen length " << src->get_length());
        uint16_t memcpy_offset = src->get_length() < 255 ? 1 : 3;

        assert(offset + src->get_length() + memcpy_offset <= length);

        memcpy(buf + offset + memcpy_offset, src->get_buf(), 
               src->get_length());

        if (memcpy_offset == 1)
          buf[offset + 0] = static_cast<uint8_t>(src->get_length());
        else {
          buf[offset + 0] = UCHAR_MAX;
          buf[offset + 1] = static_cast<uint8_t>(src->get_length() >> 8);
          buf[offset + 2] = static_cast<uint8_t>(src->get_length() >> 0);
        }

        bytes_copied = src->get_length() + memcpy_offset;
      }
      break;

    case Decision::encode_double_as_float_endianness:
      {
        float f = *static_cast<const double*>(i->address);
        assert(sizeof(f) == sizeof(uint32_t));
        std::reverse_copy(reinterpret_cast<char*>(&f),
                          reinterpret_cast<char*>(&f) + sizeof(uint32_t) - 1,
                          buf);
        
        bytes_copied = sizeof(uint32_t);
      }
      break;

    case Decision::encode_double_as_float:
      {
        float f = *static_cast<const double*>(i->address);
        assert(sizeof(f) == sizeof(uint32_t));
        memcpy(buf, &f, sizeof(uint32_t));
        bytes_copied = sizeof(uint32_t);
      }
      break;
    }

    ret += bytes_copied;
    offset += bytes_copied;
  }

  return ret;
}

namespace libfc {

PlacementExporter::PlacementExporter(uint32_t _observation_domain, uint8_t* msg_buf, 
	uint32_t msg_buf_size, uint32_t* _sequence_number_ptr)
{
	current_tpl = NULL;
	current_plan = NULL;
	sequence_number_ptr = _sequence_number_ptr;
	n_templates = 0;
	observation_domain = _observation_domain;
	buf = msg_buf;
	buf_pos = msg_buf;
	buf_size = msg_buf_size;
	buf_bytes_left = msg_buf_size;
	template_flowset_closed = false;
}

void
PlacementExporter::fini(void)
{
	for (int i=0; i<n_templates; i++)
		delete templates[i].plan;
	n_templates = 0;
}


PlacementExporter::~PlacementExporter() 
{
	fini();
}

static void 
enc16(uint16_t val, uint8_t** buf) 
{
    *(*buf)++ = (val >> 8) & 0xff;
    *(*buf)++ = (val >> 0) & 0xff;
}

static void 
enc32(uint32_t val, uint8_t** buf) {
    *(*buf)++ = (val >> 24) & 0xff;
    *(*buf)++ = (val >> 16) & 0xff;
    *(*buf)++ = (val >>  8) & 0xff;
    *(*buf)++ = (val >>  0) & 0xff;
}
      
/*
 *	Start new message
 */
int
PlacementExporter::start_message(time_t now, bool inc_sequence_number)
{
	/* reset buf */
	buf_pos = buf;

	if (buf_size < kIpfixMessageHeaderLen)
		return -1;

	buf_bytes_left = buf_size - kIpfixMessageHeaderLen;		

	/* message header */
	enc16(kIpfixVersion, &buf_pos);

	/* save place for the message length */ 
	message_len = kIpfixMessageHeaderLen;
	message_len_addr = buf_pos;
	buf_pos += sizeof(message_len);

	enc32(static_cast<uint32_t>(now), &buf_pos);
	enc32(*sequence_number_ptr, &buf_pos);
	enc32(observation_domain, &buf_pos);

	if (inc_sequence_number)
		atomic_inc_uint(sequence_number_ptr);
      
	template_flowset_closed = false;
	current_tpl = NULL;

	return 0;
}

/*
 *
 */
void
PlacementExporter::finish_message(void)
{
	libfc_printf("finish_message, msg size %hu\n", message_len);
	assert(message_len_addr != NULL);
	uint16_t _message_len = rte_cpu_to_be_16(message_len);
	memcpy(message_len_addr, &_message_len, sizeof(message_len));
}

/*
 *	Wrire template flowset
 *
 *  Returns:
 *     0 - ok
 *    <0 - error
 */


/*
 * Returns:
 *  0 - ok
 *  < 0 - error
*/
int
PlacementExporter::write_templates(void)
{
	if (n_templates == 0)
		return 0;
		
	if (buf_bytes_left < FLOWSET_HDR_LEN)
		return -1;
		
	uint16_t len = FLOWSET_HDR_LEN;
	uint8_t *len_addr;
	
	/* V10 - IPFIX */
	enc16(k_flow_set_id, &buf_pos);
	/* save space for flowset length */
	len_addr = buf_pos;
	buf_pos += sizeof(len);
	buf_bytes_left -= FLOWSET_HDR_LEN;

	libfc_printf("write templates: %hhu\n", n_templates);
	for (int i=0; i<n_templates; i++) {
		struct template_plan* tp = &templates[i];
		int tpl_size = tp->tpl->wire_template(tp->tpl_id, 
			buf_pos, buf_bytes_left);
		if (tpl_size < 0) 
			return -1;
		buf_pos += tpl_size;
		buf_bytes_left -= tpl_size;
		len += tpl_size;
	}

	/* write flowset length to the saved position */
	message_len += len;
	len = rte_cpu_to_be_16(len);
	memcpy(len_addr, &len, sizeof(len));
	return 0;
}

/*
 * Store flowset header to the buffer
       */
void 
PlacementExporter::finish_flowset(void)
{
	libfc_printf("finish_flowset: len %hu, tpl id %hu\n", flowset_len, current_tpl_id);
	
	assert(current_tpl != NULL);
	enc16(current_tpl_id, &flowset_hdr_addr);
	enc16(flowset_len, &flowset_hdr_addr);
	message_len += flowset_len;
}

void
PlacementExporter::start_flowset(void)
{
	libfc_printf("start_flowset\n");
	
	flowset_len = FLOWSET_HDR_LEN;
	/* save space in the buffer */
	flowset_hdr_addr = buf_pos;
	buf_pos += FLOWSET_HDR_LEN;
	buf_bytes_left -= FLOWSET_HDR_LEN;
}

struct template_plan*
PlacementExporter::find_template(const PlacementTemplate* tpl)
{
	for (int i=0; i<n_templates; i++)
		if (templates[i].tpl == tpl)
			return &templates[i];

	return NULL;
}

/*
 *
 */
int
PlacementExporter::add_template(PlacementTemplate* tpl, uint16_t template_id)
{
	struct template_plan* tp = find_template(tpl);
	if (tp != NULL)
		/* already exists */
		return 1;

	if (n_templates == IPFIX_MAX_TPLS)
		/* max number of templates already added */
		return -1;
	
	EncodePlan* plan = new EncodePlan(tpl);
		
	templates[n_templates].tpl = tpl;
	templates[n_templates].plan = plan;
	templates[n_templates].tpl_id = template_id;
	n_templates++;
	return 0;
}	

/*
 *
 */
void
PlacementExporter::place_values(PlacementTemplate* tpl, bool _write_templates)
{
	libfc_printf("place_values\n");
	
	if (!template_flowset_closed) {
		if (_write_templates)
			write_templates();
		template_flowset_closed = true;
	}
	
	if (tpl != current_tpl || current_tpl == NULL) {
		struct template_plan* tp = find_template(tpl);
		/* tpl should be already added */
		assert(tp);
		if (current_tpl != NULL)
			finish_flowset();
		current_tpl = tp->tpl;
		current_plan = tp->plan;
		current_tpl_id = tp->tpl_id;
		start_flowset();
	}
	
	/* write data flow */
	uint16_t offs = buf_pos - buf;
	uint16_t flow_size = current_plan->execute(buf, offs, buf_size);
	libfc_printf("flow saved %hu\n", flow_size);
	assert(buf_bytes_left >= flow_size);
	buf_pos += flow_size;
	buf_bytes_left -= flow_size;
	flowset_len += flow_size;
}

/*
 *
 */
int
PlacementExporter::complete_message(void)
{
	libfc_printf("complete_message\n");
	
	if (!template_flowset_closed) {
		int ret = write_templates();
		if (ret < 0)
			return ret;
		template_flowset_closed = true;
    }

	if (current_tpl != NULL)
		finish_flowset();

	finish_message();
	return message_len;
}

/*
 * After a reset templates should be added again.
 */
void
PlacementExporter::reset(void)
{
	template_flowset_closed = true;
	current_tpl = NULL;
	current_plan = NULL;
	fini();
}

/*
 * Set a new buffer
 */
void
PlacementExporter::set_buf(uint8_t* _buf, uint32_t _buf_size)
{
	buf = _buf;
	buf_size = _buf_size;
	buf_pos = _buf;
	buf_bytes_left = _buf_size;
	template_flowset_closed = false;
} 

} // namespace libfc
