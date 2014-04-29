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
#include <cstdint>
#include <sstream>

#ifdef _LIBFC_HAVE_LOG4CPLUS_
#  include <log4cplus/logger.h>
#  include <log4cplus/loggingmacros.h>
#else
#  define LOG4CPLUS_TRACE(logger, expr)
#endif /* _LIBFC_HAVE_LOG4CPLUS_ */

#include "Constants.h"
#include "MessageStreamParser.h"

#include "decode_util.h"

namespace IPFIX {


  MessageStreamParser::MessageStreamParser() 
    : parse_in_progress(false),
      content_handler(0),
      error_handler(0)
#ifdef _LIBFC_HAVE_LOG4CPLUS_
                      ,
      logger(log4cplus::Logger::getInstance(LOG4CPLUS_TEXT("logger")))
#endif /* _LIBFC_HAVE_LOG4CPLUS_ */
  {
  }

  void MessageStreamParser::set_error_handler(ErrorHandler* handler) {
    error_handler = handler;
  }

  void MessageStreamParser::set_content_handler(ContentHandler* handler) {
    content_handler = handler;
  }

  void MessageStreamParser::parse(InputSource& is) {
    LOG4CPLUS_TRACE(logger, "ENTER parse()");

    assert(content_handler != 0);
    assert(error_handler != 0);

    content_handler->start_session();

    if (parse_in_progress) {
      error_handler->fatal(Error::parse_while_parsing, 0);
      parse_in_progress = false;
      return;
    }
    parse_in_progress = true;

    uint8_t message[kMaxMessageLen];

    ssize_t nbytes = is.read(message, kMessageHeaderLen);
    while (nbytes > 0) {
      uint8_t* cur = message;

      /* Decode message header */
      uint16_t message_size;

      if (static_cast<size_t>(nbytes) < kMessageHeaderLen) {
        error_handler->fatal(Error::short_header, 0);
        parse_in_progress = false;
        return;
      }
      assert(static_cast<size_t>(nbytes) == kMessageHeaderLen);

      message_size = decode_uint16(cur +  2);
      content_handler->start_message(decode_uint16(cur +  0),
                                     message_size,
                                     decode_uint32(cur +  4),
                                     decode_uint32(cur +  8),
                                     decode_uint32(cur + 12),
				     0);
      
      const uint8_t* message_end = message + message_size;

      cur += nbytes;
      assert (cur <= message_end);

      nbytes = is.read(cur, message_size - kMessageHeaderLen);
      if (nbytes < 0) {
        error_handler->fatal(Error::read_error, 0);
        parse_in_progress = false;
        return;
      } else if (static_cast<size_t>(nbytes) 
                 != message_size - kMessageHeaderLen) {
        error_handler->fatal(Error::short_body, 0);
        parse_in_progress = false;
        return;
      }
      
      /* Decode sets.
       *
       * Note to prospective debuggers of the code below: I am aware
       * that the various comparisons of pointers to message
       * boundaries with "<=" instead of "<" look wrong.  After all,
       * we all write "while (p < end) p++;". But, gentle reader,
       * please be assured that these comparisons have all been
       * meticulously checked and found to be correct.  There are two
       * reasons for the use of "<=" over "<":
       *
       * (1) In one case, I check whether there are still N bytes left
       * in the buffer. In this case, if "end" points to just beyond
       * the buffer boundary, "cur + N <= end" is the correct
       * comparison. (Think about it.)
       *
       * (2) In the other case, I check that "cur" hasn't been
       * incremented to the point where it's already beyond the end of
       * the buffer, but where it's OK if it's just one byte past
       * (because that will be checked on the next iteration
       * anyway). In this case too, "cur <= end" is the correct test.
       *
       * -- Stephan Neuhaus
       */
      while (cur + kSetHeaderLen <= message_end) {
        /* Decode set header. */
        uint16_t set_id = decode_uint16(cur + 0);
        uint16_t set_length = decode_uint16(cur + 2);
        const uint8_t* set_end = cur + set_length;
        
        if (set_end > message_end) {
          std::stringstream sstr;
          sstr << "set_len=" << set_length 
               << ",set_end=" << static_cast<const void*>(set_end) 
               << ",message_len=" << message_size
               << ",message_end=" << static_cast<const void*>(message_end);
          error_handler->fatal(Error::long_set, sstr.str().c_str());
          parse_in_progress = false;
          return;
        }

        cur += kSetHeaderLen;

        if (set_id == kTemplateSetID) {
          content_handler->start_template_set(set_id,
					      set_length - kSetHeaderLen, 
					      cur);
	  cur += set_length - kSetHeaderLen;
          content_handler->end_template_set();
        } else if (set_id == kOptionTemplateSetID) {
          content_handler->start_options_template_set(set_id,
						     set_length - kSetHeaderLen,
						     cur);
          cur += set_length - kSetHeaderLen;
          content_handler->end_options_template_set();
        } else {          /* Decode data set */
          content_handler->start_data_set(set_id,
					  set_length - kSetHeaderLen,
					  cur);
          cur += set_length - kSetHeaderLen;
          content_handler->end_data_set();
        }

        assert(cur == set_end);
        assert(cur <= message_end);
      }

      content_handler->end_message();
      nbytes = is.read(message, kMessageHeaderLen);
    }

    if (nbytes < 0) {
      error_handler->fatal(Error::read_error, 0);
      parse_in_progress = false;
      return;
    }
    assert(nbytes == 0);

    parse_in_progress = false;
    content_handler->end_session();
  }

} // namespace IPFIX
