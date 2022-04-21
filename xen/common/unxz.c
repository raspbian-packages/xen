/*
 * Wrapper for decompressing XZ-compressed kernel, initramfs, and initrd
 *
 * Author: Lasse Collin <lasse.collin@tukaani.org>
 *
 * This file has been put into the public domain.
 * You can do whatever you want with this file.
 */

/*
 * Important notes about in-place decompression
 *
 * At least on x86, the kernel is decompressed in place: the compressed data
 * is placed to the end of the output buffer, and the decompressor overwrites
 * most of the compressed data. There must be enough safety margin to
 * guarantee that the write position is always behind the read position.
 *
 * The safety margin for XZ with LZMA2 or BCJ+LZMA2 is calculated below.
 * Note that the margin with XZ is bigger than with Deflate (gzip)!
 *
 * The worst case for in-place decompression is that the beginning of
 * the file is compressed extremely well, and the rest of the file is
 * uncompressible. Thus, we must look for worst-case expansion when the
 * compressor is encoding uncompressible data.
 *
 * The structure of the .xz file in case of a compresed kernel is as follows.
 * Sizes (as bytes) of the fields are in parenthesis.
 *
 *    Stream Header (12)
 *    Block Header:
 *      Block Header (8-12)
 *      Compressed Data (N)
 *      Block Padding (0-3)
 *      CRC32 (4)
 *    Index (8-20)
 *    Stream Footer (12)
 *
 * Normally there is exactly one Block, but let's assume that there are
 * 2-4 Blocks just in case. Because Stream Header and also Block Header
 * of the first Block don't make the decompressor produce any uncompressed
 * data, we can ignore them from our calculations. Block Headers of possible
 * additional Blocks have to be taken into account still. With these
 * assumptions, it is safe to assume that the total header overhead is
 * less than 128 bytes.
 *
 * Compressed Data contains LZMA2 or BCJ+LZMA2 encoded data. Since BCJ
 * doesn't change the size of the data, it is enough to calculate the
 * safety margin for LZMA2.
 *
 * LZMA2 stores the data in chunks. Each chunk has a header whose size is
 * a maximum of 6 bytes, but to get round 2^n numbers, let's assume that
 * the maximum chunk header size is 8 bytes. After the chunk header, there
 * may be up to 64 KiB of actual payload in the chunk. Often the payload is
 * quite a bit smaller though; to be safe, let's assume that an average
 * chunk has only 32 KiB of payload.
 *
 * The maximum uncompressed size of the payload is 2 MiB. The minimum
 * uncompressed size of the payload is in practice never less than the
 * payload size itself. The LZMA2 format would allow uncompressed size
 * to be less than the payload size, but no sane compressor creates such
 * files. LZMA2 supports storing uncompressible data in uncompressed form,
 * so there's never a need to create payloads whose uncompressed size is
 * smaller than the compressed size.
 *
 * The assumption, that the uncompressed size of the payload is never
 * smaller than the payload itself, is valid only when talking about
 * the payload as a whole. It is possible that the payload has parts where
 * the decompressor consumes more input than it produces output. Calculating
 * the worst case for this would be tricky. Instead of trying to do that,
 * let's simply make sure that the decompressor never overwrites any bytes
 * of the payload which it is currently reading.
 *
 * Now we have enough information to calculate the safety margin. We need
 *   - 128 bytes for the .xz file format headers;
 *   - 8 bytes per every 32 KiB of uncompressed size (one LZMA2 chunk header
 *     per chunk, each chunk having average payload size of 32 KiB); and
 *   - 64 KiB (biggest possible LZMA2 chunk payload size) to make sure that
 *     the decompressor never overwrites anything from the LZMA2 chunk
 *     payload it is currently reading.
 *
 * We get the following formula:
 *
 *    safety_margin = 128 + uncompressed_size * 8 / 32768 + 65536
 *                  = 128 + (uncompressed_size >> 12) + 65536
 *
 * For comparision, according to arch/x86/boot/compressed/misc.c, the
 * equivalent formula for Deflate is this:
 *
 *    safety_margin = 18 + (uncompressed_size >> 12) + 32768
 *
 * Thus, when updating Deflate-only in-place kernel decompressor to
 * support XZ, the fixed overhead has to be increased from 18+32768 bytes
 * to 128+65536 bytes.
 */

#include "decompress.h"

#define XZ_EXTERN static

/*
 * For boot time use, we enable only the BCJ filter of the current
 * architecture or none if no BCJ filter is available for the architecture.
 */
#ifdef CONFIG_X86
#	define XZ_DEC_X86
#endif
#ifdef CONFIG_PPC
#	define XZ_DEC_POWERPC
#endif
#ifdef CONFIG_ARM
#	define XZ_DEC_ARM
#endif
#ifdef CONFIG_IA64
#	define XZ_DEC_IA64
#endif
#ifdef CONFIG_SPARC
#	define XZ_DEC_SPARC
#endif

/*
 * This will get the basic headers so that memeq() and others
 * can be defined.
 */
#include "xz/private.h"

/*
 * memeq and memzero are not used much and any remotely sane implementation
 * is fast enough. memcpy/memmove speed matters in multi-call mode, but
 * the kernel image is decompressed in single-call mode, in which only
 * memmove speed can matter and only if there is a lot of uncompressible data
 * (LZMA2 stores uncompressible chunks in uncompressed form). Thus, the
 * functions below should just be kept small; it's probably not worth
 * optimizing for speed.
 */

#ifndef memeq
#define memeq(p1, p2, sz) (memcmp(p1, p2, sz) == 0)
#endif

#ifndef memzero
#define memzero(p, sz) memset(p, 0, sz)
#endif

#include "xz/crc32.c"
#include "xz/dec_stream.c"
#include "xz/dec_lzma2.c"
#include "xz/dec_bcj.c"

/* Size of the input and output buffers in multi-call mode */
#define XZ_IOBUF_SIZE 4096

/*
 * This function implements the API defined in <linux/decompress/generic.h>.
 *
 * This wrapper will automatically choose single-call or multi-call mode
 * of the native XZ decoder API. The single-call mode can be used only when
 * both input and output buffers are available as a single chunk, i.e. when
 * fill() and flush() won't be used.
 */
int __init unxz(unsigned char *in, unsigned int in_size,
		int (*fill)(void *dest, unsigned int size),
		int (*flush)(void *src, unsigned int size),
		unsigned char *out, unsigned int *in_used,
		void (*error)(const char *x))
{
	struct xz_buf b;
	struct xz_dec *s;
	enum xz_ret ret;
	bool_t must_free_in = false;

	xz_crc32_init();

	if (in_used != NULL)
		*in_used = 0;

	if (fill == NULL && flush == NULL)
		s = xz_dec_init(XZ_SINGLE, 0);
	else
		s = xz_dec_init(XZ_DYNALLOC, (uint32_t)-1);

	if (s == NULL)
		goto error_alloc_state;

	if (flush == NULL) {
		b.out = out;
		b.out_size = (size_t)-1;
	} else {
		b.out_size = XZ_IOBUF_SIZE;
		b.out = malloc(XZ_IOBUF_SIZE);
		if (b.out == NULL)
			goto error_alloc_out;
	}

	if (in == NULL) {
		must_free_in = true;
		in = malloc(XZ_IOBUF_SIZE);
		if (in == NULL)
			goto error_alloc_in;
	}

	b.in = in;
	b.in_pos = 0;
	b.in_size = in_size;
	b.out_pos = 0;

	if (fill == NULL && flush == NULL) {
		ret = xz_dec_run(s, &b);
	} else {
		do {
			if (b.in_pos == b.in_size && fill != NULL) {
				if (in_used != NULL)
					*in_used += b.in_pos;

				b.in_pos = 0;

				in_size = fill(in, XZ_IOBUF_SIZE);
				if ((int) in_size < 0) {
					/*
					 * This isn't an optimal error code
					 * but it probably isn't worth making
					 * a new one either.
					 */
					ret = XZ_BUF_ERROR;
					break;
				}

				b.in_size = in_size;
			}

			ret = xz_dec_run(s, &b);

			if (flush != NULL && (b.out_pos == b.out_size
					|| (ret != XZ_OK && b.out_pos > 0))) {
				/*
				 * Setting ret here may hide an error
				 * returned by xz_dec_run(), but probably
				 * it's not too bad.
				 */
				if (flush(b.out, b.out_pos) != (int)b.out_pos)
					ret = XZ_BUF_ERROR;

				b.out_pos = 0;
			}
		} while (ret == XZ_OK);

		if (must_free_in)
			free(in);

		if (flush != NULL)
			free(b.out);
	}

	if (in_used != NULL)
		*in_used += b.in_pos;

	xz_dec_end(s);

	switch (ret) {
	case XZ_STREAM_END:
		return 0;

	case XZ_MEM_ERROR:
		/* This can occur only in multi-call mode. */
		error("XZ decompressor ran out of memory");
		break;

	case XZ_FORMAT_ERROR:
		error("Input is not in the XZ format (wrong magic bytes)");
		break;

	case XZ_OPTIONS_ERROR:
		error("Input was encoded with settings that are not "
				"supported by this XZ decoder");
		break;

	case XZ_DATA_ERROR:
	case XZ_BUF_ERROR:
		error("XZ-compressed data is corrupt");
		break;

	default:
		error("Bug in the XZ decompressor");
		break;
	}

	return -1;

error_alloc_in:
	if (flush != NULL)
		free(b.out);

error_alloc_out:
	xz_dec_end(s);

error_alloc_state:
	error("XZ decompressor ran out of memory");
	return -1;
}

/*
 * This macro is used by architecture-specific files to decompress
 * the kernel image.
 */
#define decompress unxz
