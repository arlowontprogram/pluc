-- Copyright (c) 2018  Phil Leblanc  -- see LICENSE file

------------------------------------------------------------------------
--[[
	
	
=== Morus-1280

   1280-bit/160-byte state (as 20 uint64), 32-byte block
   16 or 32-byte key, 16-byte nonce

Morus Authors: Hongjun Wu, Tao Huang - Nanyang Tech University (NTU)
https://personal.ntu.edu.sg/wuhj/research/caesar/caesar.html

Morus is a finalist (round 4) in the CAESAR competition
http://competitions.cr.yp.to/caesar-submissions.html
   
---

NOTE: I have added an experimental XOF/hash function based on the 
Morus permutation. It is NOT part of the Morus submission and has NOT 
been analyzed / reviewed. The design is certainly not final.  
=> DON'T USE THE XOF/HASH FUNCTION for any serious purpose.

]]

------------------------------------------------------------------------
-- local definitions

local spack, sunpack = string.pack, string.unpack
local byte, char = string.byte, string.char
local insert, concat = table.insert, table.concat

-- debug functions
local bin = require(script.Parent.bin)
local stx, xts = bin.stohex, bin.hextos
local strf = string.format
local pf = function(fmt, ...) print(strf(fmt, ...)) end

local p48 = function(a, b, c, d) -- print 4 uint64
	b = b or 0; c = c or 0; d = d or 0
	pf("%016x %016x %016x %016x", a, b, c, d)
end

local function pst(s, msg) -- print state
	print("---", msg)
	p48(s[1], s[2], s[3], s[4])
	p48(s[5], s[6], s[7], s[8])
	p48(s[9], s[10], s[11], s[12])
	p48(s[13], s[14], s[15], s[16])
	p48(s[17], s[18], s[19], s[20])
	print("---")
end



------------------------------------------------------------------------

-- rotation constants:
--   n1 = 13
--   n2 = 46
--   n3 = 38
--   n4 = 7
--   n5 = 4

-- local function rotl(x,n) return (x << n) | (x >> (64-n)) end
-- rotate inlined in state_update()

local function state_update(s, m0, m1, m2, m3)
	local s00, s01, s02, s03 = s[1],  s[2],  s[3],  s[4]
	local s10, s11, s12, s13 = s[5],  s[6],  s[7],  s[8]
	local s20, s21, s22, s23 = s[9],  s[10], s[11], s[12]
	local s30, s31, s32, s33 = s[13], s[14], s[15], s[16]
	local s40, s41, s42, s43 = s[17], s[18], s[19], s[20]
	local temp

	--s00 = s00 ~ s30
	--s01 = s01 ~ s31
	--s02 = s02 ~ s32
	--s03 = s03 ~ s33
	s00 = bit32.bxor(s00, s30)
	s01 = bit32.bxor(s01, s31)
	s02 = bit32.bxor(s02, s32)
	s03 = bit32.bxor(s03, s33)

	temp = s33
	s33 = s32
	s32 = s31
	s31 = s30
	s30 = temp

	--s00 = s00 ~ s10 & s20
	--s01 = s01 ~ s11 & s21
	--s02 = s02 ~ s12 & s22
	--s03 = s03 ~ s13 & s23
	s00 = bit32.bxor(s00, bit32.band(s10, s20))
	s01 = bit32.bxor(s01, bit32.band(s11, s21))
	s02 = bit32.bxor(s02, bit32.band(s12, s22))
	s03 = bit32.bxor(s03, bit32.band(s13, s23))

	--s00 = (s00 << 13) | (s00 >> 51) --n1
	--s01 = (s01 << 13) | (s01 >> 51) --n1
	--s02 = (s02 << 13) | (s02 >> 51) --n1
	--s03 = (s03 << 13) | (s03 >> 51) --n1
	s00 = bit32.bor(bit32.lshift(s00, 13), bit32.rshift(s00, 51))
	s01 = bit32.bor(bit32.lshift(s01, 13), bit32.rshift(s01, 51))
	s02 = bit32.bor(bit32.lshift(s02, 13), bit32.rshift(s02, 51))
	s02 = bit32.bor(bit32.lshift(s03, 13), bit32.rshift(s03, 51))

	--s10 = s10 ~ m0
	--s11 = s11 ~ m1
	--s12 = s12 ~ m2
	--s13 = s13 ~ m3
	s10 = bit32.bxor(s10, m0)
	s11 = bit32.bxor(s11, m1)
	s12 = bit32.bxor(s12, m2)
	s13 = bit32.bxor(s13, m3)

	--s10 = s10 ~ s40
	--s11 = s11 ~ s41
	--s12 = s12 ~ s42
	--s13 = s13 ~ s43
	s10 = bit32.bxor(s10, s40)
	s11 = bit32.bxor(s11, s41)
	s12 = bit32.bxor(s12, s42)
	s13 = bit32.bxor(s13, s43)

	temp = s43
	s43 = s41
	s41 = temp

	temp = s42
	s42 = s40
	s40 = temp

	--s10 = s10 ~ (s20 & s30)
	--s11 = s11 ~ (s21 & s31)
	--s12 = s12 ~ (s22 & s32)
	--s13 = s13 ~ (s23 & s33)
	s10 = bit32.bxor(s10, bit32.band(s20, s30))
	s11 = bit32.bxor(s11, bit32.band(s21, s31))
	s12 = bit32.bxor(s12, bit32.band(s22, s32))
	s13 = bit32.bxor(s13, bit32.band(s23, s33))

	--s10 = (s10 << 46) | (s10 >> (64-46)) --n2
	--s11 = (s11 << 46) | (s11 >> (64-46)) --n2
	--s12 = (s12 << 46) | (s12 >> (64-46)) --n2
	--s13 = (s13 << 46) | (s13 >> (64-46)) --n2
	s10 = bit32.bor(bit32.lshift(s10, 46), bit32.rhsift(s10, 18))
	s11 = bit32.bor(bit32.lshift(s11, 46), bit32.rhsift(s11, 18))
	s12 = bit32.bor(bit32.lshift(s12, 46), bit32.rhsift(s12, 18))
	s13 = bit32.bor(bit32.lshift(s13, 46), bit32.rhsift(s13, 18))


	--s20 = s20 ~ m0
	--s21 = s21 ~ m1
	--s22 = s22 ~ m2
	--s23 = s23 ~ m3
	s20 = bit32.bxor(s20, m0)
	s21 = bit32.bxor(s21, m1)
	s22 = bit32.bxor(s22, m2)
	s23 = bit32.bxor(s23, m3)

	--s20 = s20 ~ s00
	--s21 = s21 ~ s01
	--s22 = s22 ~ s02
	--s23 = s23 ~ s03
	s20 = bit32.bxor(s20, s00)
	s21 = bit32.bxor(s21, s01)
	s22 = bit32.bxor(s22, s02)
	s23 = bit32.bxor(s23, s03)

	temp = s00
	s00 = s01
	s01 = s02
	s02 = s03
	s03 = temp

	--s20 = s20 ~ s30 & s40
	--s21 = s21 ~ s31 & s41
	--s22 = s22 ~ s32 & s42
	--s23 = s23 ~ s33 & s43
	s20 = bit32.bxor(s20, bit32.band(s30, s40))
	s21 = bit32.bxor(s21, bit32.band(s31, s41))
	s22 = bit32.bxor(s22, bit32.band(s32, s42))
	s23 = bit32.bxor(s23, bit32.band(s33, s43))

	--s20 = (s20 << 38) | (s20 >> (64-38)) --n3
	--s21 = (s21 << 38) | (s21 >> (64-38)) --n3
	--s22 = (s22 << 38) | (s22 >> (64-38)) --n3
	--s23 = (s23 << 38) | (s23 >> (64-38)) --n3
	s20 = bit32.bor(bit32.lshift(s20, 46), bit32.rhsift(s20, 26))
	s21 = bit32.bor(bit32.lshift(s21, 46), bit32.rhsift(s21, 26))
	s22 = bit32.bor(bit32.lshift(s22, 46), bit32.rhsift(s22, 26))
	s23 = bit32.bor(bit32.lshift(s23, 46), bit32.rhsift(s23, 26))


	--s30 = s30 ~ m0
	--s31 = s31 ~ m1
	--s32 = s32 ~ m2
	--s33 = s33 ~ m3
	s30 = bit32.bxor(s30, m0)
	s31 = bit32.bxor(s31, m1)
	s32 = bit32.bxor(s32, m2)
	s33 = bit32.bxor(s33, m3)

	--s30 = s30 ~ s10
	--s31 = s31 ~ s11
	--s32 = s32 ~ s12
	--s33 = s33 ~ s13
	s30 = bit32.bxor(s30, s10)
	s31 = bit32.bxor(s31, s11)
	s32 = bit32.bxor(s32, s12)
	s33 = bit32.bxor(s33, s13)

	temp = s13
	s13 = s11
	s11 = temp

	temp = s12
	s12 = s10
	s10 = temp

	--s30 = s30 ~ s40 & s00
	--s31 = s31 ~ s41 & s01
	--s32 = s32 ~ s42 & s02
	--s33 = s33 ~ s43 & s03
	s30 = bit32.bxor(s30, bit32.band(s40, s00))
	s31 = bit32.bxor(s31, bit32.band(s41, s01))
	s32 = bit32.bxor(s32, bit32.band(s42, s02))
	s33 = bit32.bxor(s33, bit32.band(s43, s03))

	--s30 = (s30 << 7) | (s30 >> (64-7)) --n4
	--s31 = (s31 << 7) | (s31 >> (64-7)) --n4
	--s32 = (s32 << 7) | (s32 >> (64-7)) --n4
	--s33 = (s33 << 7) | (s33 >> (64-7)) --n4
	s30 = bit32.bor(bit32.lshift(s30, 7), bit32.rhsift(s30, 57))
	s31 = bit32.bor(bit32.lshift(s31, 7), bit32.rhsift(s31, 57))
	s32 = bit32.bor(bit32.lshift(s32, 7), bit32.rhsift(s32, 57))
	s33 = bit32.bor(bit32.lshift(s33, 7), bit32.rhsift(s33, 57))


	s40 = s40 ~ m0
	s41 = s41 ~ m1
	s42 = s42 ~ m2
	s43 = s43 ~ m3
	s40 = bit32.bxor(s40, m0)
	s41 = bit32.bxor(s41, m1)
	s42 = bit32.bxor(s42, m2)
	s43 = bit32.bxor(s43, m3)

	--s40 = s40 ~ s20
	--s41 = s41 ~ s21
	--s42 = s42 ~ s22
	--s43 = s43 ~ s23
	s40 = bit32.bxor(s40, s20)
	s41 = bit32.bxor(s41, s21)
	s42 = bit32.bxor(s42, s22)
	s43 = bit32.bxor(s43, s23)

	temp = s23
	s23 = s22
	s22 = s21
	s21 = s20
	s20 = temp

	--s40 = s40 ~ s00 & s10
	--s41 = s41 ~ s01 & s11
	--s42 = s42 ~ s02 & s12
	--s43 = s43 ~ s03 & s13
	s40 = bit32.bxor(s40, bit32.band(s00, s10))
	s41 = bit32.bxor(s41, bit32.band(s01, s11))
	s42 = bit32.bxor(s42, bit32.band(s02, s12))
	s43 = bit32.bxor(s43, bit32.band(s03, s13))

	--s40 = (s40 << 4) | (s40 >> (64-4)) --n5
	--s41 = (s41 << 4) | (s41 >> (64-4)) --n5
	--s42 = (s42 << 4) | (s42 >> (64-4)) --n5
	--s43 = (s43 << 4) | (s43 >> (64-4)) --n5
	s40 = bit32.bor(bit32.lshift(s40, 4), bit32.rhsift(s40, 60))
	s41 = bit32.bor(bit32.lshift(s41, 4), bit32.rhsift(s41, 60))
	s42 = bit32.bor(bit32.lshift(s42, 4), bit32.rhsift(s42, 60))
	s43 = bit32.bor(bit32.lshift(s43, 4), bit32.rhsift(s43, 60))

	-- update the state array
	s[1],  s[2],  s[3],  s[4]  = s00, s01, s02, s03
	s[5],  s[6],  s[7],  s[8]  = s10, s11, s12, s13
	s[9],  s[10], s[11], s[12] = s20, s21, s22, s23
	s[13], s[14], s[15], s[16] = s30, s31, s32, s33
	s[17], s[18], s[19], s[20] = s40, s41, s42, s43

end--state_update()

local function enc_aut_step(s, m0, m1, m2, m3)
	--         m0   s00    s11    s20     s30
	--local c0 = m0 ~ s[1] ~ s[6] ~ (s[9]  & s[13])
	local c0 = bit32.bxor(m0, s[1], s[6], bit32.band(s[9], s[13]))
	--         m1   s01    s12    s21     s31
	--local c1 = m1 ~ s[2] ~ s[7] ~ (s[10] & s[14])
	local c1 = bit32.bxor(m1, s[2], s[7], bit32.band(s[10], s[14]))
	--         m2   s02    s13    s22     s32
	--local c2 = m2 ~ s[3] ~ s[8] ~ (s[11] & s[15])
	local c2 = bit32.bxor(m2, s[3], s[8], bit32.band(s[11], s[15]))
	--         m3   s03    s10    s23     s33
	--local c3 = m3 ~ s[4] ~ s[5] ~ (s[12] & s[16])
	local c3 = bit32.bxor(m3, s[4], s[9], bit32.band(s[12], s[16]))
	state_update(s, m0, m1, m2, m3)
	return c0, c1, c2, c3
end

local function dec_aut_step(s, c0, c1, c2, c3, blen)
	-- mlen is the length of a last partial block
	-- mlen is absent/nil for full blocks
	-- return the decrypted block
	--
	--         m0   s00    s11    s20     s30
	--local c0 = m0 ~ s[1] ~ s[6] ~ (s[9]  & s[13])
	local m0 = bit32.bxor(c0, s[1], s[6], bit32.band(s[9], s[13]))
	--         m1   s01    s12    s21     s31
	--local c1 = m1 ~ s[2] ~ s[7] ~ (s[10] & s[14])
	local m1 = bit32.bxor(c1, s[2], s[7], bit32.band(s[10], s[14]))
	--         m2   s02    s13    s22     s32
	--local c2 = m2 ~ s[3] ~ s[8] ~ (s[11] & s[15])
	local m2 = bit32.bxor(c2, s[3], s[8], bit32.band(s[11], s[15]))
	--         m3   s03    s10    s23     s33
	--local c3 = m3 ~ s[4] ~ s[5] ~ (s[12] & s[16])
	local m3 = bit32.bxor(c3, s[4], s[9], bit32.band(s[12], s[16]))
	if blen then 
		-- partial block => must adjust (m0, ...) before
		-- updating the state
		local mblk = spack("<I8I8I8I8", m0, m1, m2, m3):sub(1, blen) 
		local blk = mblk .. string.rep('\0', 32 - blen)
		assert(#blk == 32, #blk)
		m0, m1, m2, m3 = sunpack("<I8I8I8I8", blk)
		state_update(s, m0, m1, m2, m3)
		return mblk
	end
	-- full block
	state_update(s, m0, m1, m2, m3)
	return spack("<I8I8I8I8", m0, m1, m2, m3)
end

-- state init constants (fibonacci)
-- u8 con[32] = {
--	0x00,0x01,0x01,0x02,0x03,0x05,0x08,0x0d
--	,0x15,0x22,0x37,0x59,0x90,0xe9,0x79,0x62
--	,0xdb,0x3d,0x18,0x55,0x6d,0xc2,0x2f,0xf1
--	,0x20,0x11,0x31,0x42,0x73,0xb5,0x28,0xdd
local con = { -- con as 4 uint64 -  !! assume little endian !!
		0xd08050302010100, 0x6279e99059372215, 
	    0xf12fc26d55183ddb, 0xdd28b57342311120 }
	
local function state_init(key, iv)
	-- return an initialized state array
	assert((#key == 16) or (#key == 32), "key must be 16 or 32 bytes")
	assert(#iv == 16, "iv must be 16 bytes")
	local ek0, ek1, ek2, ek3 
	if #key == 16 then 
		ek0, ek1 = sunpack("<I8I8", key)
		ek3, ek2 = ek1, ek0
	else
		ek0, ek1, ek2, ek3 = sunpack("<I8I8I8I8", key)
	end
	local iv0, iv1 = sunpack("<I8I8", iv)
	--initaialize state s:
	local s = {
		iv0, iv1, 0, 0,                 -- state[0][]
		ek0, ek1, ek2, ek3,             -- state[1][]
		-1, -1, -1, -1,                 -- state[2][]  (0xff * 32)
		0, 0, 0, 0,                     -- state[3][]
		con[1], con[2], con[3], con[4], -- state[4][]
	}
	for i = 1, 16 do state_update(s, 0, 0, 0, 0) end
	--s[5] = s[5] ~ ek0  -- state[1][i] ^= ((uint64_t*)ekey)[i];
	--s[6] = s[6] ~ ek1
	--s[7] = s[7] ~ ek2
	--s[8] = s[8] ~ ek3
	s[5] = bit32.bxor(s[5], ek0)
	s[6] = bit32.bxor(s[6], ek1)
	s[7] = bit32.bxor(s[7], ek2)
	s[8] = bit32.bxor(s[8], ek3)
	return s
end--state_init()

--finalization

local function tag_compute(s, mlen, adlen)
	-- return tag0, tag1 (the tag as two uint64)
	--local m0, m1, m2, m3 = (adlen << 3), (mlen << 3), 0, 0
	local m0, m1, m2, m3 = bit32.lshift(adlen, 3), bit32.lshift(mlen, 3), 0, 0

	-- s[1],  s[2],  s[3],  s[4]  = s00, s01, s02, s03
	-- s[5],  s[6],  s[7],  s[8]  = s10, s11, s12, s13
	-- s[9],  s[10], s[11], s[12] = s20, s21, s22, s23
	-- s[13], s[14], s[15], s[16] = s30, s31, s32, s33
	-- s[17], s[18], s[19], s[20] = s40, s41, s42, s43

	-- state[4][0] ^= state[0][0]; state[4][1] ^= state[0][1]; 
	-- state[4][2] ^= state[0][2]; state[4][3] ^= state[0][3];
	--s[17] = s[17] ~ s[1];  s[18] = s[18] ~ s[2]
	s[17] = bit32.bxor(s[17], s[1])
	s[18] = bit32.bxor(s[18], s[2])
	--s[19] = s[19] ~ s[3];  s[20] = s[20] ~ s[4]
	s[19] = bit32.bxor(s[19], s[3])
	s[20] = bit32.bxor(s[20], s[4])
	for i = 1, 10 do state_update(s, m0, m1, m2, m3) end
	-- for (j = 0; j < 4; j++) {
	--	state[0][j] ^= state[1][(j + 1) & 3] ^ (state[2][j] & state[3][j]);}
	--s[1] = s[1] ~ s[6] ~ (s[9] & s[13]) -- j=0
	s[1] = bit32.bxor(s[1], s[6], bit32.band(s[9], s[13]))
	--s[2] = s[2] ~ s[7] ~ (s[10] & s[14]) -- j=1
	s[2] = bit32.bxor(s[2], s[7], bit32.band(s[10], s[14]))
	--s[3] = s[3] ~ s[8] ~ (s[11] & s[15]) -- j=2
	s[3] = bit32.bxor(s[3], s[8], bit32.band(s[11], s[15]))
	--s[4] = s[4] ~ s[5] ~ (s[12] & s[16]) -- j=3
	s[4] = bit32.bxor(s[4], s[5], bit32.band(s[12], s[16]))
	-- [why compute s[3], s[4]?  for a 32-byte mac?]
	--
	return s[1], s[2] -- tag is state[0][0]..state[0][1]
end-- tag_compute

local function encrypt(k, iv, m, ad)
	-- k is the encryption key (16 or 32-byte string)
	-- iv is the nonce or initial value (16-byte string)
	-- m is the message to encrypt (variable length string)
	-- ad is the additional data (variable length string)
	-- ad is optional and defaults to ""
	-- return the encrypted message e as a string (ad .. c .. tag)
	-- where ad is the non-encrypted additional data, c is the encypted 
	-- message and tag is the 16-byte authentication MAC.
	-- #e = #ad + #m + 16
	ad = ad or ""
	local mlen, adlen = #m, #ad
	local m0, m1, m2, m3, c0, c1, c2, c3
	local blk, blen
	local ct = {} -- used to collect ad, encrypted blocks and tag
	-- init
	local s = state_init(k, iv)
	-- absorb ad
	local i = 1
	while i <= adlen - 31 do --process full blocks
		m0, m1, m2, m3 = sunpack("<I8I8I8I8", ad, i)
		i = i + 32
		enc_aut_step(s, m0, m1, m2, m3)
	end
	if i <= adlen then -- process last, partial block of ad
		blk = ad:sub(i) .. string.rep('\0', 31 + i - adlen)
		assert(#blk == 32, #blk)
		m0, m1, m2, m3 = sunpack("<I8I8I8I8", blk)
		enc_aut_step(s, m0, m1, m2, m3)
	end
	insert(ct, ad) -- collect the ad in ct
	-- encrypt m
	i = 1
	while i <= mlen - 31 do --process full blocks
		m0, m1, m2, m3 = sunpack("<I8I8I8I8", m, i)
		i = i + 32
		--c0, c1, c2, c3 = m0, m1, m2, m3 --use this to test overhead perf
		c0, c1, c2, c3 = enc_aut_step(s, m0, m1, m2, m3)
		-- collect the 32 encrypted bytes in ct
		insert(ct, spack("<I8I8I8I8", c0, c1, c2, c3))
	end
	if i <= mlen then -- process last, partial block of m
		blk = m:sub(i) -- last partial block
		blen = #blk
		blk = blk .. string.rep('\0', 31 + i - mlen)
		assert(#blk == 32, #blk)
		m0, m1, m2, m3 = sunpack("<I8I8I8I8", blk)
		c0, c1, c2, c3 = enc_aut_step(s, m0, m1, m2, m3)
		-- collect the last blen encrypted bytes in ct
		insert(ct, spack("<I8I8I8I8", c0, c1, c2, c3):sub(1, blen))
	end
	-- compute the mac
	local tag0, tag1 = tag_compute(s, mlen, adlen)
	insert(ct, spack("<I8I8", tag0, tag1))
	-- return the complete encrypted message (with ad prefix and tag suffix)
	return table.concat(ct) 
end--encrypt()


local function decrypt(k, iv, e, adlen)
	-- k is the encryption key (16-byte string)
	-- iv is the nonce or initial value (16-byte string)
	-- e is the encrypted message
	-- adlen is the length of the additional data at the start of e
	-- adlen is optional and defaults to 0
	-- return the plain text message message m as a string 
	-- or nil, error msg if the authentication tag is not valid
	-- #m = #e - adlen - 16
	adlen = adlen or 0
	local elen = #e - 16  -- length of msg before tag
	local mlen = elen - adlen
	local m0, m1, m2, m3, c0, c1, c2, c3
	local blk, blen
	local ct = {}  -- used to collect decrypted blocks
	-- init
	local s = state_init(k, iv)
	-- absorb ad
	if adlen > 0 then ad = e:sub(1, adlen) end
	local i = 1
	while i <= adlen - 31 do --process full blocks
		m0, m1, m2, m3 = sunpack("<I8I8I8I8", ad, i)
		i = i + 32
		enc_aut_step(s, m0, m1, m2, m3)
	end
	if i <= adlen then -- process last, partial block of ad
		blk = ad:sub(i) .. string.rep('\0', 31 + i - adlen)
		assert(#blk == 32, #blk)
		m0, m1, m2, m3 = sunpack("<I8I8I8I8", blk)
		enc_aut_step(s, m0, m1, m2, m3)
	end
	-- decrypt message
	i = adlen + 1
	while i <= elen - 31 do --process full blocks
		c0, c1, c2, c3 = sunpack("<I8I8I8I8", e, i)
		i = i + 32
		blk = dec_aut_step(s, c0, c1, c2, c3)
		-- collect the 32 decrypted bytes in ct
		insert(ct, blk)
	end
	if i <= elen then -- process last, partial block of m
		blk = e:sub(i, elen) -- last partial block
		blen = #blk
		blk = blk .. string.rep('\0', 31 + i - elen)
		assert(#blk == 32, #blk)
		c0, c1, c2, c3 = sunpack("<I8I8I8I8", blk)
		blk = dec_aut_step(s, c0, c1, c2, c3, blen)
		insert(ct, blk)
	end
	-- check the mac
	local ctag0, ctag1 = tag_compute(s, mlen, adlen)
	local tag0, tag1 = sunpack("<I8I8", e, elen + 1)
	if ((ctag0 ~ tag0) | (ctag1 ~ tag1)) ~= 0 then
		return nil, "decrypt error"
	end
	-- return the decrypted message 
	return table.concat(ct) 
end--decrypt()


local function xof(m, outlen, key)
	--
	-- !! EXPERIMENTAL - NOT DESIGNED BY THE MORUS AUTHORS !! 
	-- !! => DON'T USE IT FOR ANYTHING !! 
	--
	-- a keyed extendable-output function (XOF) built on the morus
	-- permutation.
	-- m is the message to hash. outlen is the optional length of 
	-- the output in bytes (defaults to 32 - can be any number > 1)
	-- key is an optional string that is mixed to the initial 
	-- permutation state. key can be any length. if longer 
	-- than 32 bytes, only the first 32 bytes are used.
	--
	outlen = outlen or 32 
	key = key or ""
	key = key .. ('\0'):rep(32 - #key)
	local mlen = #m
	local m0, m1, m2, m3
	local blk, blen
	--
	--initialize state s:
	local iv = spack("<I8I8", outlen, 0)
	local s = state_init(key, iv)
	--
	-- absorb m
	local i = 1
	while i <= mlen - 31 do --process full blocks
		m0, m1, m2, m3 = sunpack("<I8I8I8I8", m, i)
		i = i + 32
		state_update(s,  m0, m1, m2, m3)
	end
	--
	-- absorb last, partial block of m, pad as needed
	-- (minimal padding - same as original keccak: "01 0* 1"; 
	-- no domain constant before the first 01 bits) 
	-- => padding for last block is:   b | 01 | 00 00 ... | 80
	--              or, if #b == 31:   b | 81
	if mlen - i < 30 then 
		blk = m:sub(i) .. '\x01' .. ('\0'):rep(29 - (mlen - i)) .. '\x80'
		assert(#blk == 32, #blk)
	else -- mlen-i == 30 -- only one byte of padding
		blk = m:sub(i) .. '\x81'
	end
	m0, m1, m2, m3 = sunpack("<I8I8I8I8", blk)
	state_update(s,  m0, m1, m2, m3)
	--
	-- mix the state before squeezing (mostly useful for short messages)
	for i = 1, 16 do state_update(s, 0, 0, 0, 0) end
	--
	-- squeeze output
	local outt = {} -- used to collect output blocks
	local n = 0
	repeat
		blk = spack("<I8I8I8I8", s[1],s[2],s[3],s[4])
		state_update(s, 0, 0, 0, 0)
		-- collect 32 (rate) bytes at each turn
		n = n + 32
		if n > outlen then
			blk = blk:sub(1, outlen - (n - 32))
			n = outlen
		end
		insert(outt, blk)
	until n >= outlen
	local out = concat(outt)
	assert(#out == outlen)
	return out
end--xof()


------------------------------------------------------------------------
-- the morus module

return {
	-- the core permutation is exposed to facilitate tests 
	state_update = state_update,
	--
	encrypt = encrypt,
	decrypt = decrypt,
	--
	key_size = 32,
	nonce_size = 16,
	variant = "Morus-1280",
	--
	xof = xof,  -- experimental!! - don't use it for anything!!
	
}


