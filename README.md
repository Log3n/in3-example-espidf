# Embedded Devices


## Hardware Requirements
### Memory 


| Memory type                 | Free size KB |
| ------------------------ | -------- |
| **Dynamic memory(DRAM)** | 30 - 50   |
| **Flash Memory**         | 150 - 200   |


### Networking
In3 client needs to have a reliable internet connection to work properly, so your hardware must support any network interface or module that could give you acccess. i.e  bluetooth, wifi, ethernet, etc.
        
## Incubed with ESP-IDF



### Use case example: Airbnb Property access

A smart door lock which enables accessing the rented flat is installed on the property. It is able to connect to the Internet to check if renting is allowed and the current user is authorized to open the lock.

The computational power of the control unit is restricted to the control of the lock. And it is also needed to maintain a permanent Internet connection.

You want to enable this in your application as an example of how in3 can help you, we will guide trough the steps of doing it, from the very basics and the resources you will need 

**Hardware requirements**

![from https://docs.espressif.com/projects/esp-idf/en/stable/get-started/](https://i.imgur.com/IVgORi4.png)


* [ESP32-DevKitC V4](https://docs.espressif.com/projects/esp-idf/en/latest/hw-reference/get-started-devkitc.html) or similar dev board
* Android phone
* Laptop MAC, Linux, Windows
* USB Cable 

**Software requirements** 

*  [In3](https://github.com/slockit/in3-c) C client
*  Esp-idf toolchain and sdk, (please follow this [guide](https://docs.espressif.com/projects/esp-idf/en/stable/get-started/)) 
*  [Android Studio](https://developer.android.com/studio)
* Solidity smart contract:  we will control access to properties using a public smart contract, for this example we will use the following template

```
pragma solidity ^0.5.1;

contract Access {
    uint8 access;
    constructor() public  {
        access = 0;
    }
    
    function hasAccess() public view returns(uint8) {
        return access;
    }
    
    function setAccess(uint8 accessUpdate) public{
        access = accessUpdate;
    }
}
```

**How it works**
![sequence diagram](https://i.imgur.com/l36Yobm.png)



in3 will support a variety on microcontrollers for this we will use well known esp32 with freertos framework, and a example android app to interact with it via Wifi connection. 

**Instalation instructions**
1. Clone the repo

`git clone https://github.com/slockit/in3-devices-esp `

2. Follow [esp-idf](https://) instructions to setup your environment


3. Deploy the contract with your favorite tool (truffle, etc) or use our previusly deployed contract on goerli, with address `0x36643F8D17FE745a69A2Fd22188921Fade60a98B`



4. To setup the password and ssid of your network, go to kconfig esp menu with: 
`idf.py menuconfig`
then select component config
![](https://i.imgur.com/iVtqGig.png)
then in3 at then end of the list, 
![](https://i.imgur.com/uIPhf9l.png)
then you will will be able to input your credentials and be safe you are not hardcoding them in your code
![](https://i.imgur.com/6AtcPFA.png)


5. Build the code
`idf.py build`

6. Connect the usb cable to flash and monitor the serial output from the application. 

`idf.py flash && idf.py monitor`

after the build finishes and the serial monitor is running you will see the configuration and init logs.

7. Configure the ip address of the example, to work with:
Take a look at the inital output of the serial output of the `idf.py monitor` command, you will the ip address, as follows 

```
I (2647) tcpip_adapter: sta ip: 192.168.178.64, mask: 255.255.255.0, gw: 192.168.178.1
I (2647) IN3: got ip:192.168.178.64
```
take note if your ip address which will be used in the android application example. 

8. Clone the android repository, compile the android application and install the in3 demo application in your phone. 

`git clone https://github.com/slockit/in3-android-example`


9. Modify the android source changing ip address variable inside kotlin source file `MainActivity.kt`

`(L:20) private const val ipaddress = "http://192.168.xx.xx"`

With the IP address found on step 6. 



## Incubed with Zephyr

....(Comming soon)

