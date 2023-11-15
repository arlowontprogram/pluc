-- Copyright (c) 2014  Joseph Wallace
-- Copyright (c) 2015  Phil Leblanc
-- License: MIT - see LICENSE file
------------------------------------------------------------

-- 170612 SHA-3 padding fixed.
-- (reported by Michael Rosenberg https://github.com/doomrobo)

-- 150827 original code modified and optimized
-- (more than 2x performance improvement for sha3-512) --phil

-- Directly devived from a Keccak implementation by Joseph Wallace
-- published on the Lua mailing list in 2014
-- http://lua-users.org/lists/lua-l/2014-03/msg00905.html


------------------------------------------------------------
-- sha3 / keccak

local char	= string.char
local concat	= table.concat
local spack, sunpack = string.pack, string.unpack

-- the Keccak constants and functionality

local ROUNDS = 24

local roundConstants = {
0x0000000000000001,
0x0000000000008082,
0x800000000000808A,
0x8000000080008000,
0x000000000000808B,
0x0000000080000001,
0x8000000080008081,
0x8000000000008009,
0x000000000000008A,
0x0000000000000088,
0x0000000080008009,
0x000000008000000A,
0x000000008000808B,
0x800000000000008B,
0x8000000000008089,
0x8000000000008003,
0x8000000000008002,
0x8000000000000080,
0x000000000000800A,
0x800000008000000A,
0x8000000080008081,
0x8000000000008080,
0x0000000080000001,
0x8000000080008008
}

local rotationOffsets = {
-- ordered for [x][y] dereferencing, so appear flipped here:
{0, 36, 3, 41, 18},
{1, 44, 10, 45, 2},
{62, 6, 43, 15, 61},
{28, 55, 25, 21, 56},
{27, 20, 39, 8, 14}
}



-- the full permutation function
local function keccakF(st)
	local permuted = st.permuted
	local parities = st.parities
	for round = 1, ROUNDS do
--~ 		local permuted = permuted
--~ 		local parities = parities

		-- theta()
		for x = 1,5 do
			parities[x] = 0
			local sx = st[x]
			for y = 1,5 do parities[x] = bit32.bxor(parities[x], sx[y]) end
		end
		--
		-- unroll the following loop
		--for x = 1,5 do
		--	local p5 = parities[(x)%5 + 1]
		--	local flip = parities[(x-2)%5 + 1] ~ ( p5 << 1 | p5 >> 63)
		--	for y = 1,5 do st[x][y] = st[x][y] ~ flip end
		--end
		local p5, flip, s
		local function bit_flip(s, x, parities)
			local flip = parities[x] ~ (parities[x - 1] << 1 | parities[x - 1] >> 63)
			for y = 1, 5 do
				s[y] = s[y] ~ flip
			end
		end
				
		for x = 2, 5 do
			bit_flip(st[x - 1], x, parities)
		end
		
		bit_flip(st[5], 1, parities)

		-- rhopi()
		for y = 1,5 do
			local py = permuted[y]
			local r
			for x = 1,5 do
				s, r = st[x][y], rotationOffsets[x][y]
				py[(2 * x + 3 * y) % 5 + 1] = bit32.bor(bit32.lshift(s, r) | bit32.rshift(s, 64 - r))
			end
		end

		-- chi() - unroll the loop
		--for x = 1,5 do
		--	for y = 1,5 do
		--		local combined = (~ permuted[(x)%5 +1][y]) & permuted[(x+1)%5 +1][y]
		--		st[x][y] = permuted[x][y] ~ combined
		--	end
		--end

		local function applyOperations(st, permuted, roundConstants, round)
			local function applyOperation(s, p, p1, p2)
				for y = 1, 5 do
					s[y] = p[y] ~ (~p1[y]) & p2[y]
				end
			end
		
			local xValues = {1, 2, 3, 4, 5}
			local permutedIndices = {1, 2, 3, 4, 5}
		
			for i = 1, 5 do
				local x = xValues[i]
				local permutedIndex = permutedIndices[i]
		
				local s = st[x]
				local p = permuted[permutedIndex]
				local p1 = permuted[permutedIndex % 5 + 1]
				local p2 = permuted[permutedIndex % 5 + 2]
		
				applyOperation(s, p, p1, p2)
			end
		
			st[1][1] = st[1][1] ~ roundConstants[round]
		end
		
		applyOperations(st, permuted, roundConstants, round)
	end
end


local function absorb(st, buffer)

	local blockBytes = st.rate / 8
	local blockWords = blockBytes / 8

	-- append 0x01 byte and pad with zeros to block size (rate/8 bytes)
	local totalBytes = #buffer + 1
	-- for keccak (2012 submission), the padding is byte 0x01 followed by zeros
	-- for SHA3 (NIST, 2015), the padding is byte 0x06 followed by zeros

	-- Keccak:
	-- buffer = buffer .. ( '\x01' .. char(0):rep(blockBytes - (totalBytes % blockBytes)))

	-- SHA3:
	buffer = buffer .. ( '\x06' .. char(0):rep(blockBytes - (totalBytes % blockBytes)))
	totalBytes = #buffer

	--convert data to an array of u64
	local words = {}
	for i = 1, totalBytes - (totalBytes % 8), 8 do
		words[#words + 1] = sunpack('<I8', buffer, i)
	end

	local totalWords = #words
	-- OR final word with 0x80000000 to set last bit of state to 1
	words[totalWords] = bit32.bor(words[totalWords], 0x8000000000000000)

	-- XOR blocks into state
	for startBlock = 1, totalWords, blockWords do
		local offset = 0
		for y = 1, 5 do
			for x = 1, 5 do
				if offset < blockWords then
					local index = startBlock+offset
					st[x][y] = bit32.bxor(st[x][y], words[index])
					offset += 1
				end
			end
		end
		keccakF(st)
	end
end


-- returns [rate] bits from the state, without permuting afterward.
-- Only for use when the state will immediately be thrown away,
-- and not used for more output later
local function squeeze(st)
	local blockBytes = st.rate / 8
	local blockWords = blockBytes / 4
	-- fetch blocks out of state
	local hasht = {}
	local offset = 1
	for y = 1, 5 do
		for x = 1, 5 do
			if offset < blockWords then
				hasht[offset] = spack("<I8", st[x][y])
				offset += 1
			end
		end
	end
	return concat(hasht)
end


-- primitive functions (assume rate is a whole multiple of 64 and length is a whole multiple of 8)

local function keccakHash(rate, length, data)
	local state = {	{0,0,0,0,0},
					{0,0,0,0,0},
					{0,0,0,0,0},
					{0,0,0,0,0},
					{0,0,0,0,0},
	}
	state.rate = rate
	-- these are allocated once, and reused
	state.permuted = { {}, {}, {}, {}, {}, }
	state.parities = {0,0,0,0,0}
	absorb(state, data)
	return squeeze(state):sub(1,length/8)
end

-- output raw bytestrings
local function keccak256Bin(data) return keccakHash(1088, 256, data) end
local function keccak512Bin(data) return keccakHash(576, 512, data) end

--return module
return {
	sha256 = keccak256Bin,
	sha512 = keccak512Bin,
}
