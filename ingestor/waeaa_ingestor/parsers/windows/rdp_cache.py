"""Windows Remote Desktop (RDP) Bitmap Cache proprietary parser and screen reconstructor.

Parses .bmc (legacy) and .bin (RDP 8+) cache files, extracts 64x64 pixel bitmap tiles,
saves them to disk, and applies an edge-pixel matching algorithm to assemble tiles
into reconstructed desktop screenshot mosaics.
"""

from __future__ import annotations

import math
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

from waeaa_ingestor.parsers.base import BaseParser, ParsedRecord


@dataclass
class RdpTile:
    """A single 64x64 pixel bitmap tile extracted from an RDP cache."""

    index: int
    cache_file: str
    width: int = 64
    height: int = 64
    bpp: int = 32
    bgra_data: bytes = b""
    hash_key: int = 0

    def to_bmp(self) -> bytes:
        """Encode 64x64 tile as a standard, universally compatible 24-bit bottom-up Windows BMP."""
        row_size = self.width * 3
        image_size = row_size * self.height
        file_size = 54 + image_size

        # Invert scanlines to bottom-up order (standard Windows BMP format)
        # and extract 24-bit BGR from 32-bit BGRA to guarantee universal viewer compatibility
        # and eliminate transparency/black-box rendering artifacts.
        pixel_data = bytearray(image_size)
        stride_in = self.width * 4
        for y in range(self.height):
            src_row = y * stride_in
            dst_row = (self.height - 1 - y) * row_size
            for x in range(self.width):
                px_in = src_row + x * 4
                px_out = dst_row + x * 3
                pixel_data[px_out : px_out + 3] = self.bgra_data[px_in : px_in + 3]

        header = struct.pack(
            "<2sIHHI" "IiiHHIIiiII",
            b"BM",
            file_size,
            0,
            0,
            54,  # Offset to pixel data
            40,  # DIB header size (BITMAPINFOHEADER)
            self.width,
            self.height,  # Positive height = standard bottom-up row order
            1,  # Planes
            24,  # 24bpp BI_RGB (BGR)
            0,  # BI_RGB uncompressed
            image_size,
            2835,  # 72 DPI X
            2835,  # 72 DPI Y
            0,
            0,
        )
        return header + pixel_data

    def get_right_edge(self) -> list[tuple[int, int, int]]:
        """Return RGB tuples of the 64 pixels along the right column."""
        edge = []
        stride = self.width * 4
        for y in range(self.height):
            idx = y * stride + (self.width - 1) * 4
            b, g, r = self.bgra_data[idx : idx + 3]
            edge.append((r, g, b))
        return edge

    def get_left_edge(self) -> list[tuple[int, int, int]]:
        """Return RGB tuples of the 64 pixels along the left column."""
        edge = []
        stride = self.width * 4
        for y in range(self.height):
            idx = y * stride
            b, g, r = self.bgra_data[idx : idx + 3]
            edge.append((r, g, b))
        return edge

    def get_bottom_edge(self) -> list[tuple[int, int, int]]:
        """Return RGB tuples of the 64 pixels along the bottom row."""
        edge = []
        start = (self.height - 1) * self.width * 4
        for x in range(self.width):
            idx = start + x * 4
            b, g, r = self.bgra_data[idx : idx + 3]
            edge.append((r, g, b))
        return edge

    def get_top_edge(self) -> list[tuple[int, int, int]]:
        """Return RGB tuples of the 64 pixels along the top row."""
        edge = []
        for x in range(self.width):
            idx = x * 4
            b, g, r = self.bgra_data[idx : idx + 3]
            edge.append((r, g, b))
        return edge


def edge_distance(
    edge_a: list[tuple[int, int, int]], edge_b: list[tuple[int, int, int]]
) -> float:
    """Calculate mean Euclidean distance between matching pixels on two adjacent tile edges."""
    if len(edge_a) != len(edge_b) or not edge_a:
        return 9999.0
    total = 0.0
    for (r1, g1, b1), (r2, g2, b2) in zip(edge_a, edge_b, strict=False):
        total += abs(r1 - r2) + abs(g1 - g2) + abs(b1 - b2)
    return total / len(edge_a)


@dataclass
class ReconstructedScreen:
    """A composite reconstructed desktop screenshot composed of matched tiles."""

    screen_id: int
    cols: int
    rows: int
    tile_indices: list[list[int | None]] = field(default_factory=list)
    bmp_bytes: bytes = b""
    tile_count: int = 0


class RdpCacheParser(BaseParser):
    """Proprietary zero-dependency parser for RDP Bitmap Cache (.bmc and .bin) files."""

    def can_parse(self, file_path: str) -> bool:
        """Report whether file_path matches genuine RDP bitmap cache criteria."""
        lower = file_path.lower().replace("\\", "/")
        filename = Path(lower).name

        # Must have cache extension (.bin or .bmc)
        if not (lower.endswith(".bin") or lower.endswith(".bmc")):
            return False

        # Strictly check if located under Terminal Server Client Cache directory
        is_rdp_dir = "terminal server client/cache" in lower or "terminal server client\\cache" in lower
        if is_rdp_dir:
            return True

        # Or explicit RDP client cache file naming: bcache*.bmc, bcache*.bin, cache*.bin
        if filename.startswith("bcache") or filename.startswith("cache0") or filename.startswith("cache1"):
            return True

        return False

    def parse(self, stream: IO[bytes], file_path: str) -> Iterator[ParsedRecord]:
        """Parse RDP cache files, extract tiles, and yield ParsedRecords."""
        data = stream.read()
        if len(data) < 64:
            return

        tiles = self.extract_tiles(data, file_path)
        if not tiles:
            return

        yield ParsedRecord(
            artefact_type="RDPCache",
            source_file=file_path,
            timestamp_utc="",
            action="RdpBitmapCacheParsed",
            summary=f"Extracted {len(tiles)} bitmap tiles (64x64) from {Path(file_path).name}",
            details={
                "tile_count": len(tiles),
                "cache_file": Path(file_path).name,
                "first_tile_index": tiles[0].index if tiles else 0,
            },
        )

    def extract_tiles(self, data: bytes, file_path: str) -> list[RdpTile]:
        """Extract 64x64 bitmap tiles from binary RDP cache stream."""
        tiles: list[RdpTile] = []
        name = Path(file_path).name.lower()

        # Format detection: .bmc vs .bin
        if name.endswith(".bmc"):
            tiles = self._extract_bmc_tiles(data, file_path)
        else:
            tiles = self._extract_bin_tiles(data, file_path)

        return tiles

    def _extract_bin_tiles(self, data: bytes, file_path: str) -> list[RdpTile]:
        """Extract tiles from modern RDP 8+ .bin cache files."""
        tiles: list[RdpTile] = []
        offset = 0
        file_len = len(data)

        # Check for modern RDP 8 container header:
        # Signature "RDP8bmp\x00" (8 bytes) + 4 bytes version = 12 bytes
        if data.startswith(b"RDP8bmp\x00"):
            offset = 12
        elif data.startswith(b"RDP8BMCACHE"):
            offset = 32
        elif file_len >= 16 and data[:4] == b"\x00\x00\x00\x00":
            offset = 16

        idx = 0
        # In RDP 8+ .bin cache, each tile entry has a 12-byte header:
        # key1 (4 bytes, uint32) + key2 (4 bytes, uint32) + width (2 bytes, uint16) + height (2 bytes, uint16)
        # Followed by uncompressed 32bpp pixel data: width * height * 4 bytes (typically 64x64x4 = 16384 bytes).
        while offset + 12 <= file_len:
            key1, key2, w, h = struct.unpack_from("<LLHH", data, offset)

            # Valid tile dimensions: typically 64x64 (or up to 64)
            if 0 < w <= 64 and 0 < h <= 64:
                payload_len = w * h * 4
                payload_start = offset + 12
                payload_end = payload_start + payload_len

                if payload_end <= file_len:
                    raw_pixels = data[payload_start:payload_end]
                    bgra = self._normalize_to_bgra(raw_pixels, w, h)
                    tiles.append(
                        RdpTile(
                            index=idx,
                            cache_file=Path(file_path).name,
                            width=64,
                            height=64,
                            bpp=32,
                            bgra_data=bgra,
                            hash_key=(key2 << 32) | key1,
                        )
                    )
                    idx += 1
                    # In RDP 8+, tile slots are fixed at 16396 bytes (12 header + 16384 payload)
                    advance = 12 + max(payload_len, 16384)
                    offset += advance
                    continue

            # If slot header is empty/deleted (key1=0, key2=0, w=0, h=0) in a 16396-byte slot container
            if offset + 16396 <= file_len:
                next_offset = offset + 16396
                if next_offset + 12 <= file_len:
                    _, _, nw, nh = struct.unpack_from("<LLHH", data, next_offset)
                    if 0 < nw <= 64 and 0 < nh <= 64:
                        offset = next_offset
                        continue

            # Fallback for raw headerless 16384 (32bpp) or 12288 (24bpp) streams
            if offset + 16384 <= file_len:
                raw_chunk = data[offset : offset + 16384]
                bgra = self._normalize_to_bgra(raw_chunk, 64, 64)
                tiles.append(
                    RdpTile(
                        index=idx,
                        cache_file=Path(file_path).name,
                        width=64,
                        height=64,
                        bpp=32,
                        bgra_data=bgra,
                        hash_key=idx,
                    )
                )
                idx += 1
                offset += 16384
            elif offset + 12288 <= file_len:
                raw_chunk = data[offset : offset + 12288]
                bgra = self._convert_24bpp_to_32bpp(raw_chunk)
                tiles.append(
                    RdpTile(
                        index=idx,
                        cache_file=Path(file_path).name,
                        width=64,
                        height=64,
                        bpp=32,
                        bgra_data=bgra,
                        hash_key=idx,
                    )
                )
                idx += 1
                offset += 12288
            else:
                break

        return tiles

    def _extract_bmc_tiles(self, data: bytes, file_path: str) -> list[RdpTile]:
        """Extract tiles from legacy .bmc cache files."""
        tiles: list[RdpTile] = []
        name = Path(file_path).name.lower()
        is_24bpp = "24" in name
        tile_size = 12288 if is_24bpp else 8192

        # Check if header is 64 bytes, 32 bytes, or 0
        if (len(data) - 64) % tile_size == 0:
            offset = 64
        elif (len(data) - 32) % tile_size == 0:
            offset = 32
        else:
            offset = 0

        idx = 0
        while offset + tile_size <= len(data):
            raw_tile = data[offset : offset + tile_size]
            bgra = (
                self._convert_24bpp_to_32bpp(raw_tile)
                if is_24bpp
                else self._convert_16bpp_to_32bpp(raw_tile)
            )

            tiles.append(
                RdpTile(
                    index=idx,
                    cache_file=Path(file_path).name,
                    width=64,
                    height=64,
                    bpp=32,
                    bgra_data=bgra,
                    hash_key=idx,
                )
            )
            idx += 1
            offset += tile_size

        return tiles

    def _normalize_to_bgra(self, data: bytes, width: int = 64, height: int = 64) -> bytes:
        """Convert arbitrary tile payload (16bpp, 24bpp, 32bpp) into 64x64 32-bit BGRA bytes with full opacity."""
        expected_32 = width * height * 4
        if len(data) == width * height * 3:
            raw = self._convert_24bpp_to_32bpp(data)
        elif len(data) == width * height * 2:
            raw = self._convert_16bpp_to_32bpp(data)
        elif len(data) >= expected_32:
            raw = data[:expected_32]
        else:
            raw = data + b"\x00" * (expected_32 - len(data))

        # Enforce Alpha = 255 (100% opaque) for every pixel
        out = bytearray(raw)
        for i in range(3, len(out), 4):
            out[i] = 255
        return bytes(out)

    def _convert_24bpp_to_32bpp(self, bgr_data: bytes) -> bytes:
        """Expand 24-bit BGR pixel stream into 32-bit BGRA (Alpha=255)."""
        out = bytearray(len(bgr_data) // 3 * 4)
        out_idx = 0
        for i in range(0, len(bgr_data) - 2, 3):
            out[out_idx] = bgr_data[i]  # B
            out[out_idx + 1] = bgr_data[i + 1]  # G
            out[out_idx + 2] = bgr_data[i + 2]  # R
            out[out_idx + 3] = 255  # A
            out_idx += 4
        return bytes(out)

    def _convert_16bpp_to_32bpp(self, rgb565_data: bytes) -> bytes:
        """Convert 16-bit RGB 5-6-5 pixels into 32-bit BGRA."""
        out = bytearray(len(rgb565_data) // 2 * 4)
        out_idx = 0
        for i in range(0, len(rgb565_data) - 1, 2):
            val = rgb565_data[i] | (rgb565_data[i + 1] << 8)
            r = ((val >> 11) & 0x1F) * 255 // 31
            g = ((val >> 5) & 0x3F) * 255 // 63
            b = (val & 0x1F) * 255 // 31
            out[out_idx] = b
            out[out_idx + 1] = g
            out[out_idx + 2] = r
            out[out_idx + 3] = 255
            out_idx += 4
        return bytes(out)


class ScreenReconstructor:
    """Assembles RDP 64x64 tiles into composite reconstructed desktop screens using edge matching."""

    @staticmethod
    def build_grid_mosaic(
        tiles: list[RdpTile], max_cols: int = 16, max_tiles: int = 256
    ) -> ReconstructedScreen:
        """Arrange tiles in temporal sequence onto a grid canvas and return a composite BMP."""
        subset = tiles[:max_tiles]
        if not subset:
            return ReconstructedScreen(screen_id=0, cols=0, rows=0)

        n = len(subset)
        cols = min(n, max_cols)
        rows = math.ceil(n / cols)

        canvas_w = cols * 64
        canvas_h = rows * 64
        stride = canvas_w * 4
        canvas = bytearray(stride * canvas_h)

        grid: list[list[int | None]] = [[None for _ in range(cols)] for _ in range(rows)]

        for idx, t in enumerate(subset):
            r = idx // cols
            c = idx % cols
            grid[r][c] = t.index

            tile_data = t.bgra_data
            for ty in range(64):
                dst_y = r * 64 + ty
                dst_offset = dst_y * stride + (c * 64 * 4)
                src_offset = ty * 64 * 4
                canvas[dst_offset : dst_offset + 256] = tile_data[src_offset : src_offset + 256]

        bmp_data = ScreenReconstructor._encode_canvas_bmp(canvas, canvas_w, canvas_h)
        return ReconstructedScreen(
            screen_id=1,
            cols=cols,
            rows=rows,
            tile_indices=grid,
            bmp_bytes=bmp_data,
            tile_count=n,
        )

    @staticmethod
    def build_matched_screenshot(tiles: list[RdpTile], cols: int = 20, rows: int = 12) -> ReconstructedScreen:
        """Assemble a screen using greedy horizontal and vertical edge pixel matching."""
        if not tiles:
            return ReconstructedScreen(screen_id=0, cols=cols, rows=rows)

        used = set()
        grid: list[list[RdpTile | None]] = [[None for _ in range(cols)] for _ in range(rows)]

        # Place initial seed tile in top-left
        grid[0][0] = tiles[0]
        used.add(0)

        # Greedy edge-matching placement
        for r in range(rows):
            for c in range(cols):
                if grid[r][c] is not None:
                    continue

                best_tile: RdpTile | None = None
                best_score = 999999.0

                # Target edges to match
                left_cell = grid[r][c - 1] if c > 0 else None
                top_cell = grid[r - 1][c] if r > 0 else None
                target_left = left_cell.get_right_edge() if left_cell is not None else None
                target_top = top_cell.get_bottom_edge() if top_cell is not None else None

                for candidate_idx, candidate in enumerate(tiles):
                    if candidate_idx in used:
                        continue

                    score = 0.0
                    matches = 0
                    if target_left:
                        dist_h = edge_distance(target_left, candidate.get_left_edge())
                        score += dist_h
                        matches += 1
                    if target_top:
                        dist_v = edge_distance(target_top, candidate.get_top_edge())
                        score += dist_v
                        matches += 1

                    if matches > 0:
                        avg_score = score / matches
                        if avg_score < best_score:
                            best_score = avg_score
                            best_tile = candidate

                # Threshold: if match is reasonable (distance < 55) or sequential fallback
                if best_tile and best_score < 55.0:
                    grid[r][c] = best_tile
                    used.add(best_tile.index)
                else:
                    # Sequential unused fallback
                    for candidate_idx, candidate in enumerate(tiles):
                        if candidate_idx not in used:
                            grid[r][c] = candidate
                            used.add(candidate_idx)
                            break

        # Render grid to canvas
        canvas_w = cols * 64
        canvas_h = rows * 64
        stride = canvas_w * 4
        canvas = bytearray(stride * canvas_h)
        tile_count = 0
        idx_grid: list[list[int | None]] = []

        for r in range(rows):
            row_indices: list[int | None] = []
            for c in range(cols):
                t = grid[r][c]
                if t:
                    tile_count += 1
                    row_indices.append(t.index)
                    for ty in range(64):
                        dst_y = r * 64 + ty
                        dst_offset = dst_y * stride + (c * 64 * 4)
                        src_offset = ty * 64 * 4
                        canvas[dst_offset : dst_offset + 256] = t.bgra_data[src_offset : src_offset + 256]
                else:
                    row_indices.append(None)
            idx_grid.append(row_indices)

        bmp_data = ScreenReconstructor._encode_canvas_bmp(canvas, canvas_w, canvas_h)
        return ReconstructedScreen(
            screen_id=2,
            cols=cols,
            rows=rows,
            tile_indices=idx_grid,
            bmp_bytes=bmp_data,
            tile_count=tile_count,
        )

    @staticmethod
    def _encode_canvas_bmp(canvas: bytearray, width: int, height: int) -> bytes:
        """Encode raw BGRA buffer as standard 24-bit bottom-up Windows BMP."""
        row_pad = (4 - (width * 3) % 4) % 4
        row_size = width * 3 + row_pad
        image_size = row_size * height
        file_size = 54 + image_size

        pixel_data = bytearray(image_size)
        stride_in = width * 4

        for y in range(height):
            src_row = y * stride_in
            dst_row = (height - 1 - y) * row_size
            for x in range(width):
                px_in = src_row + x * 4
                px_out = dst_row + x * 3
                pixel_data[px_out : px_out + 3] = canvas[px_in : px_in + 3]

        header = struct.pack(
            "<2sIHHI" "IiiHHIIiiII",
            b"BM",
            file_size,
            0,
            0,
            54,
            40,
            width,
            height,
            1,
            24,
            0,
            image_size,
            2835,
            2835,
            0,
            0,
        )
        return header + pixel_data
