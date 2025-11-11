# Programming / Bring up 
There's 3 total steps needed to be taken to prepare a blank board. Ideally in this order:
* Program the FTDI [.xml](https://raw.githubusercontent.com/Pheeeeenom/360-Lizard-RE/refs/heads/main/sw/FTDI/internal%20EEPROM_PD_true.xml)
* Program the PIC18F87J11 with the [.hex](https://raw.githubusercontent.com/Pheeeeenom/360-Lizard-RE/refs/heads/main/sw/MCU/lizard_v1.34_last_official_fw.hex)
* Program the SPI chip [.bin](https://github.com/Pheeeeenom/360-Lizard-RE/raw/refs/heads/main/sw/SPI/spi_v1.34_last_official_fw.bin)

# FTDI

Use FT_Prog to apply the .xml inside sw/FTDI/.

# PIC18F87J11

Use a [PICKIT 3](https://amazon.com/dp/B07PHPBP3Y) and use the [standalone programmer](https://ww1.microchip.com/downloads/en/DeviceDoc/PICkit_3_Programmer_1_0_Setup_A.zip)

<div align="center">
  <img src="https://github.com/Pheeeeenom/360-Lizard-RE/blob/main/res/PIC_Programming.png?raw=true" alt="PIC Settings">
</div>

<p align="center">
Select the appropriate PIC from the device drop down then select Target Power On checkbox (be sure you do **NOT** select /MCLR). Lastly, select the .hex and click the write button.
</p>

# SPI Chip

<div align="center">
  <img src="https://github.com/Pheeeeenom/360-Lizard-RE/blob/main/res/updater_tool.png?raw=true" alt="updater settings">
</div>

Use the [updater tool](https://github.com/Pheeeeenom/360-Lizard-RE/raw/refs/heads/main/sw/LizardFwUpdater_work_deob.exe) and click on "2 - Flash Update" then click connect and once it connects click Flash Device and select the .bin just wait.
