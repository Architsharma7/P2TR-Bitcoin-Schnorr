# -------------------------
# Elliptic Curve Parameters
# -------------------------
# these are the parameters for secp256k1, which is the same curve used in ECDSA

import math
from hashlib import sha256

# y² = x³ + ax + b
A = 0
B = 7

# prime field
P = 115792089237316195423570985008687907853269984665640564039457584007908834671663 #=> 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

# number of points on the curve we can hit ("order")
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337 #=> 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# generator point (the starting point on the curve used for all calculations)
G = {
  "x": 55066263022277343669578718895168534326250603453777594175500187360389116729240, #=> 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
  "y": 32670510020758816978083085130507043184471273380659243275938904335757337482424, #=> 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
}

# --------------------------
# Elliptic Curve Mathematics
# --------------------------

# Modular Inverse
def inverse(a, m=P):
    return pow(a % m, -1, m)

# Double: add a point to itself
def double(point):
  # check for point at infinity (greatest common divisor between 2y and p isn't 1)
  if (math.gcd((2 * point["y"]) % P, P) != 1): # taken from BitcoinECDSA.php
    raise ValueError("Point at infinity.")

  # slope = (3x₁² + a) / 2y₁
  slope = ((3 * pow(point["x"], 2, P) + A) * inverse((2 * point["y"]), P)) % P # using inverse to help with division

  # x = slope² - 2x₁
  x = (pow(slope, 2, P) - (2 * point["x"])) % P

  # y = slope * (x₁ - x) - y₁
  y = (slope * (point["x"] - x) - point["y"]) % P

  # Return the new point¢ªº
  return { "x": x, "y": y }

# Add: add two points together
def add(point1, point2):
  # double if both points are the same
  if point1 == point2:
    return double(point1)

  # check for point at infinity (greatest common divisor between x1-x2 and p isn't 1)
  if (math.gcd((point1["x"] - point2["x"]) % P, P) != 1): # taken from BitcoinECDSA.php
    raise ValueError("Point at infinity.")

  # slope = (y₁ - y₂) / (x₁ - x₂)
  slope = ((point1["y"] - point2["y"]) * inverse(point1["x"] - point2["x"], P)) % P

  # x = slope² - x₁ - x₂
  x = (pow(slope, 2, P) - point1["x"] - point2["x"]) % P

  # y = slope * (x₁ - x) - y₁
  y = ((slope * (point1["x"] - x)) - point1["y"]) % P

  # Return the new point
  return { "x": x, "y": y }

# Multiply: use double and add operations to quickly multiply a point by an integer value (i.e. a private key)
def mul(k, point = G):
  # create a copy the initial starting point (for use in addition later on)
  current = { "x": point["x"], "y": point["y"] }

  # convert integer to binary representation
  binary = bin(k)[2:]

  # double and add algorithm for fast multiplication
  for char in list(binary)[1:]: # from left to right, ignoring first binary character
    # 0 = double
    current = double(current)

    # 1 = double and add
    if char == "1":
      current = add(current, point)

  # return the final point
  return current

# ----------------
# BIP340 Functions (Schnorr Signatures)
# ----------------

# convert hexadecimal string of bytes to integer
def int_from_hex(hex_bytes):
  return int(hex_bytes, 16)

# convert integer to hexadecimal string of bytes
def hex32(i):
  return format(i, "064x") # convert to hex and pad with zeros to make it 32 bytes (64 characters)

# hash some data using SHA256 with a tag prefix
def tagged_hash(tag, message):

  # create a hash of the tag first
  tag_hash = sha256(tag.encode()).hexdigest() # hash the string directly

  # prefix the message with the tag hash (the tag_hash is prefixed twice so that the prefix is 64 bytes in total)
  preimage = bytes.fromhex(tag_hash + tag_hash + message) # also convert to byte sequence before hashing

  # SHA256(tag_hash || tag_hash || message)
  result = sha256(preimage).hexdigest();

  return result

# convert public key (x coordinate only) in to a point - lift_x() in BIP 340
def lift_x(public_key):
  x = int_from_hex(public_key) # convert from x coordinate from hex to an integer
  y_sq = (pow(x, 3, P) + 7) % P # use the elliptic curve equation (y² = x³ + ax + b) to work out the value of y from x
  y = pow(y_sq, (P+1)//4, P) # secp256k1 is chosen in a special way so that the square root of y is y^((p+1)/4)

  # check that x coordinate is less than the field size
  if x >= P:
    raise ValueError("x value in public key is not a valid coordinate because it is not less than the elliptic curve field size")

  # verify that the computed y value is the square root of y_sq (otherwise the public key was not a valid x coordinate on the curve)
  if (pow(y, 2, P)) != y_sq:
    raise ValueError("public key is not a valid x coordinate on the curve")

  # if the calculated y value is odd, negate it to get the even y value instead (for this x-coordinate)
  if y % 2 != 0:
    y = P - y

  # public key point
  public_key_point = {"x": x, "y": y}

  return public_key_point

# ----------------
# BIP341 Functions (Taproot)
# ----------------

# calculate control byte from leaf version and parity of tweaked public key
def calculate_control_byte(leaf_version, tweaked_pubkey_point):
	
	# set parity bit based on whether y is even or odd
	if (tweaked_pubkey_point["y"] % 2 == 0):
		parity_bit = 0 # y is even
	else:
		parity_bit = 1 # y is odd
	
	control_byte = field(dechex(leaf_version + parity_bit), 1)
	
	return control_byte

# -----------------
# General Functions
# -----------------

def dechex(dec):
  return int(dec).__format__("x")

def field(field_hex, size=4):
  return str(field_hex).rjust(size*2, '0')

# swap endianness
def reversebytes(hexstr):
  h = str(hexstr)
  if len(h) % 2 != 0:
    h = "0" + h
  return "".join(reversed([h[i:i+2] for i in range(0, len(h), 2)]))

def compact_size(i):
  if (i <= 252):
    result = field(dechex(i), 1)
  elif (i > 252 and i <= 65535):
    result = 'fd' + field(dechex(i), 2)
  elif (i > 65535  and i <= 4294967295):
    result = 'fe' + field(dechex(i), 4)
  elif (i > 4294967295 and i <= 18446744073709551615):
    result = 'ff' + field(dechex(i), 8)
  else:
    raise ValueError("integer too large for CompactSize")

  return result

def h2i(h: str) -> int:
  return int(h, 16)

def i2h(x: int, size: int = 32) -> str:
  return f"{x:0{size*2}x}"

# add compact size field to start of scriptpubkey
def serialize_script(script):
  # get length of script as number of bytes
  length = len(script) // 2
  
  # return script with compact size prepended
  return compact_size(length) + script
