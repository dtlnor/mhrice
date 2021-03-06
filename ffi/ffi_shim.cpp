#include "astc-codec/include/astc-codec/astc-codec.h"
#include "bc7/bc7decomp.h"

using namespace bc7decomp;
using namespace astc_codec;


void fill_error(std::uint8_t block_width, std::uint8_t block_height,
        std::uint8_t* out_buffer) {

    for (std::uint8_t i = 0; i < block_width * block_height; ++i) {
        *(out_buffer++) = 0xFF;
        *(out_buffer++) = 0;
        *(out_buffer++) = 0xFF;
        *(out_buffer++) = 0xFF;
    }
}
extern "C" {
    void bc7_decompress_block_ffi(const std::uint8_t* input_buffer, std::uint8_t* out_buffer) {
        color_rgba pixels[16];
        if (unpack_bc7(input_buffer, pixels)) {
            for (int i = 0; i < 16; ++i) {
                out_buffer[i * 4] = pixels[i].r;
                out_buffer[i * 4 + 1] = pixels[i].g;
                out_buffer[i * 4 + 2] = pixels[i].b;
                out_buffer[i * 4 + 3] = pixels[i].a;
            }
        } else {
            fill_error(4, 4, out_buffer);
        }
    }

    void astc_decompress_block_ffi(
        const std::uint8_t* astc_data,
        std::uint8_t block_width, std::uint8_t block_height,
        std::uint8_t* out_buffer) {


        FootprintType footprint;

        if (block_width == 4 && block_height == 4) {
            footprint = FootprintType::k4x4;
        } else if (block_width == 5 && block_height == 4) {
            footprint = FootprintType::k5x4;
        } else if (block_width == 5 && block_height == 5) {
            footprint = FootprintType::k5x5;
        } else if (block_width == 6 && block_height == 5) {
            footprint = FootprintType::k6x5;
        } else if (block_width == 6 && block_height == 6) {
            footprint = FootprintType::k6x6;
        } else if (block_width == 8 && block_height == 5) {
            footprint = FootprintType::k8x5;
        } else if (block_width == 8 && block_height == 6) {
            footprint = FootprintType::k8x6;
        } else if (block_width == 10 && block_height == 5) {
            footprint = FootprintType::k10x5;
        } else if (block_width == 10 && block_height == 6) {
            footprint = FootprintType::k10x6;
        } else if (block_width == 8 && block_height == 8) {
            footprint = FootprintType::k8x8;
        } else if (block_width == 10 && block_height == 8) {
            footprint = FootprintType::k10x8;
        } else if (block_width == 10 && block_height == 10) {
            footprint = FootprintType::k10x10;
        } else if (block_width == 12 && block_height == 10) {
            footprint = FootprintType::k12x10;
        } else if (block_width == 12 && block_height == 12) {
            footprint = FootprintType::k12x12;
        } else {
            fill_error(block_width, block_height, out_buffer);
            return;
        }

        if (!ASTCDecompressToRGBA(astc_data, 16, block_width, block_height, footprint, out_buffer,
            block_width * block_height * 4, block_width * 4)) {
            fill_error(block_width, block_height, out_buffer);
        }
    }
}
