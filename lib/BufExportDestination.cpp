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
#include <unistd.h>
#include <errno.h>

#include "Constants.h"
#include "BufExportDestination.h"

namespace libfc {

BufExportDestination::BufExportDestination(char* _buf, size_t _buf_size): 
	buf(_buf), buf_size(_buf_size), buf_offs(0)
{
}

ssize_t
BufExportDestination::writev(const std::vector< ::iovec>& iovecs) {
	const struct iovec *iov = iovecs.data();
	for (unsigned i=0; i<iovecs.size(); i++,iov++) {
		if (iov->iov_len > buf_size - buf_offs)
			/* not enougth space int the buffer */
			return -1;
		memcpy(&buf[buf_offs], iov->iov_base, iov->iov_len);
		buf_offs+=iov->iov_len;
	}
	return 0;
}

int 
BufExportDestination::flush() {
	return 0;
}

bool 
BufExportDestination::is_connectionless() const {
	return false;
}

size_t BufExportDestination::preferred_maximum_message_size() const {
	return kMaxMessageLen;
}

size_t BufExportDestination::bytes_written() const {
	return buf_offs;
}

void 
BufExportDestination::reset_buffer(char* _buf, size_t _buf_size) {
	buf_offs = 0;
	buf = _buf;
	buf_size = _buf_size;
}

} // namespace libfc
