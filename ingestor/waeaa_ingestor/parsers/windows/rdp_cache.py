"""Windows Remote Desktop (RDP) Bitmap Cache proprietary parser and screen reconstructor.

Parses .bmc (legacy) and .bin (RDP 8+) cache files, extracts 64x64 pixel bitmap tiles,
saves them to disk, and applies an edge-pixel matching algorithm to assemble tiles
into reconstructed desktop screenshot mosaics.
"""

from __future__ import annotations

import io
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
        """Encode 64x64 BGRA tile as a standalone Windows BMP file."""
        row_size = self.width * (self.bpp // 8)
        image_size = row_size * self.height
        file_size = 54 + image_size

        # BMP Header (14 bytes) + DIB Header BITMAPINFOHEADER (40 bytes)
        # Top-down bitmap specified by negative height (-64)
        header = struct.pack(
            "<2sIHHI" "IiiHHIIiiII",
            b"BM",
            file_size,
            0,
            0,
            54,  # Offset to pixel data
            40,  # DIB header size
            self.width,
            -self.height,  # Negative height = top-down row order
            1,  # Planes
            self.bpp,
            0,  # BI_RGB uncompressed
            image_size,
            2835,  # 72 DPI X
            2835,  # 72 DPI Y
            0,
            0,
        )
        return header + self.bgra_data

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
        """Report whether file_path matches RDP cache naming conventions."""
        lower = file_path.lower().replace("\\", "/")
        is_cache_path = "terminal server client/cache" in lower or "mstsc" in lower
        has_ext = lower.endswith(".bin") or lower.endswith(".bmc")
        is_rdp_name = "bcache" in lower or "cache" in lower
        return (is_cache_path and has_ext) or (is_rdp_name and has_ext)

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

        # Heuristic format detection: .bmc vs .bin
        if name.endswith(".bmc"):
            tiles = self._extract_bmc_tiles(data, file_path)
        else:
            tiles = self._extract_bin_tiles(data, file_path)

        return tiles

    def _extract_bin_tiles(self, data: bytes, file_path: str) -> list[RdpTile]:
        """Extract tiles from modern RDP 8+ .bin cache files."""
        tiles: list[RdpTile] = []
        offset = 0

        # Optional RDP8BMCACHE magic header (12-32 bytes)
        if data.startswith(b"RDP8BMCACHE"):
            offset = 32
        elif len(data) >= 16 and data[:4] == b"\x00\x00\x00\x00":
            offset = 16

        idx = 0
        while offset + 16 <= len(data):
            # Probe for tile header:
            # HashKey (8 bytes) + Width (2 bytes) + Height (2 bytes) + DataLen (4 bytes)
            # Typically Width=64 (0x40), Height=64 (0x40)
            hash_key, w, h = struct.unpack_from("<QHH", data, offset)
            if w == 64 and h == 64 and offset + 16 <= len(data):
                data_len = struct.unpack_from("<I", data, offset + 12)[0]
                chunk_len = data_len if (0 < data_len <= 16384) else (64 * 64 * 4)

                payload_start = offset + 16
                payload_end = payload_start + chunk_len
                if payload_end <= len(data):
                    tile_data = data[payload_start:payload_end]
                    bgra = self._normalize_to_bgra(tile_data, w, h)
                    tiles.append(
                        RdpTile(
                            index=idx,
                            cache_file=Path(file_path).name,
                            width=64,
                            height=64,
                            bpp=32,
                            bgra_data=bgra,
                            hash_key=hash_key,
                        )
                    )
                    idx += 1
                    offset = payload_end
                    continue

            # Fallback sequential chunk scanner
            # Check for uncompressed 32bpp tile (16384 bytes) or 24bpp (12288 bytes)
            if offset + 16384 <= len(data):
                raw_chunk = data[offset : offset + 16384]
                tiles.append(
                    RdpTile(
                        index=idx,
                        cache_file=Path(file_path).name,
                        width=64,
                        height=64,
                        bpp=32,
                        bgra_data=raw_chunk,
                        hash_key=idx,
                    )
                )
                idx += 1
                offset += 16384
            elif offset + 12288 <= len(data):
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
            if is_24bpp:
                bgra = self._convert_24bpp_to_32bpp(raw_tile)
            else:
                bgra = self._convert_16bpp_to_32bpp(raw_tile)

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
        """Convert arbitrary tile payload (16bpp, 24bpp, 32bpp) into 64x64 32-bit BGRA bytes."""
        expected_32 = width * height * 4
        if len(data) == expected_32:
            return data
        if len(data) == width * height * 3:
            return self._convert_24bpp_to_32bpp(data)
        if len(data) == width * height * 2:
            return self._convert_16bpp_to_32bpp(data)

        # Pad or truncate to 32bpp
        if len(data) < expected_32:
            return data + b"\x00" * (expected_32 - len(data))
        return data[:expected_32]

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
                target_left = grid[r][c - 1].get_right_edge() if (c > 0 and grid[r][c - 1]) else None
                target_top = grid[r - 1][c].get_bottom_edge() if (r > 0 and grid[r - 1][c]) else None

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
        """Encode raw BGRA buffer as top-down Windows BMP."""
        row_size = width * 4
        image_size = row_size * height
        file_size = 54 + image_size

        header = struct.pack(
            "<2sIHHI" "IiiHHIIiiII",
            b"BM",
            file_size,
            0,
            0,
            54,
            40,
            width,
            -height,
            1,
            32,
            0,
            image_size,
            2835,
            2835,
            0,
            0,
        )
        return header + canvas
