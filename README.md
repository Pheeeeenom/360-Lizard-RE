# 360-Lizard-RE
This is a completely reverse engineered 360 Lizard. The ultimate xbox 360 flashing tool.

# Retaining Serial Number
Get your serial number prior to doing anything by connecting your existing lizard to the PC and opening the toolbox.
# Intel HEX Checksum Calculation

## Steps
1. **Ignore** the starting colon (`:`).  
2. **Sum** all bytes in the record:
   - Byte count  
   - Address (2 bytes)  
   - Record type  
   - Data bytes  
3. **Keep only** the least significant byte of the sum (sum mod 256).  
4. **Compute the two’s complement**:
5. **Append** the checksum as the last byte.

## Example

Record without checksum: 
:1003F000B13AECEB8DCB4B3C93C79ED3398739A5


---

## Step 1: Split the record

| Field | Bytes | Description |
|-------|--------|-------------|
| Byte count | `10` | 16 data bytes |
| Address | `03 F0` | Start address 0x03F0 |
| Record type | `00` | Data record |
| Serial | `B1 3A EC EB 8D CB 4B 3C 93 C7 9E D3 39 87 39 A5` | 16 bytes |

---

## Step 2: Add all bytes (except the colon and checksum)


Let’s add step by step (hex math, keeping only 8-bit sum each time):

| Operation | Sum (Hex) |
|------------|------------|
| 10 + 03 | 13 |
| 13 + F0 | 103 → 03 |
| 03 + 00 | 03 |
| 03 + B1 | B4 |
| B4 + 3A | EE |
| EE + EC | 1DA → DA |
| DA + EB | 1C5 → C5 |
| C5 + 8D | 152 → 52 |
| 52 + CB | 11D → 1D |
| 1D + 4B | 68 |
| 68 + 3C | A4 |
| A4 + 93 | 137 → 37 |
| 37 + C7 | FE |
| FE + 9E | 19C → 9C |
| 9C + D3 | 16F → 6F |
| 6F + 39 | A8 |
| A8 + 87 | 12F → 2F |
| 2F + 39 | 68 |
| 68 + A5 | 10D → **0D** |

Final sum (mod 256) = **0x0D**

---

## Step 3: Take the two’s complement

0x100 - 0x0D = 0xF3

## Step 4: Append the checksum

Final Intel HEX record: :1003F000B13AECEB8DCB4B3C93C79ED3398739A5F3


## Step 5: Insert this at the appropriate line in the correct location in the hex

You can ctrl+f to find ":1003F000F1C70B8FBAF25C6CF312CC823655D6D1B2" which is the serial + checksum in the latest 1.34 hex.
