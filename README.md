# ilitek_ld_tool
This tool is targeted for ILITEK touch controller for ChromeOS touch firmware update

**How to build:**
```
$ make
```
**How to run:**
```
sudo ilitek_ld <Cmd> [<Cmd Options>]

  <Cmd> support below command list
    Chrome        Get FW version only
    PanelInfor    Get all ILITEK TP info.
    FWUpgrade     FW Update to specific FW file

  <Cmd Options>
    -h/--help    Show more cmd options help message
```
**How to perform a Firmware Update:**
```
sudo ilitek_ld FWUpgrade -i <*.hex/*.bin file path>

  *.hex/*.bin should follow ILITEK format
```
