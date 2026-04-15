/*
    zlib: CVE-2022-37434 
    
    Target symbols: inflate, inflateGetHeader
    
    These are normal decompression API functions. We compress a small
    buffer with deflate, then decompress with inflate. We also call
    inflateGetHeader to exercise both probed symbols.
*/ 


#include <stdio.h>
#include <string.h>
#include <zlib.h>

int main(void) {
    const char *input = "Hello from the Lizt eval workload. This is benign data.";
    uLong input_len = (uLong)strlen(input);

    uLong compressed_len = compressBound(input_len);
    unsigned char compressed[4096];
    int ret = compress(compressed, &compressed_len,
                       (const unsigned char *)input, input_len);
    if (ret != Z_OK) {
        fprintf(stderr, "compress() failed: %d\n", ret);
        return 1;
    }
    printf("[zlib] Compressed %lu -> %lu bytes\n", input_len, compressed_len);

    // Decompress with inflate (target symbol #1)
    z_stream strm = {0};
    ret = inflateInit(&strm);
    if (ret != Z_OK) {
        fprintf(stderr, "inflateInit() failed: %d\n", ret);
        return 1;
    }

    unsigned char output[4096];
    strm.next_in = compressed;
    strm.avail_in = (uInt)compressed_len;
    strm.next_out = output;
    strm.avail_out = sizeof(output);

    ret = inflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END) {
        fprintf(stderr, "inflate() did not complete: %d\n", ret);
        inflateEnd(&strm);
        return 1;
    }
    printf("[zlib] inflate() called successfully — decompressed %lu bytes\n",
           strm.total_out);
    inflateEnd(&strm);

    // Call inflateGetHeader (target symbol #2)
    // NOTE: inflateGetHeader only works with gzip streams (inflateInit2 with
    // windowBits = 15+16). We init a gzip inflate context and call
    // inflateGetHeader — it will return Z_OK even without data.
    z_stream gz_strm = {0};
    ret = inflateInit2(&gz_strm, 15 + 16);  // gzip decoding
    if (ret != Z_OK) {
        fprintf(stderr, "inflateInit2() failed: %d\n", ret);
        return 1;
    }

    gz_header header = {0};
    ret = inflateGetHeader(&gz_strm, &header);
    printf("[zlib] inflateGetHeader() called — returned %d\n", ret);
    inflateEnd(&gz_strm);

    printf("[zlib] Workload complete.\n");
    return 0;
}