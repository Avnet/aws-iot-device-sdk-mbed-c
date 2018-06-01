This code is the same as the aws-it-device-sdk-embedded-C (https://github.com/aws/aws-iot-device-sdk-embedded-C) only modified to run on the ARM mbed-os v5.x operating system using the easy-connect library for connectivity.  Two example programs are provided to demonstrate operation
1. MQTT subscribe/publish 
2. AWS Shadow operation.

Comprehensive documentation on the operation of these examples is provided at: https://docs.aws.amazon.com/iot/latest/developerguide/iot-embedded-c-sdk.html

# Note
  for the samples to run correctly, ensure the STM32 Nucleo-L476RG and Quectel BG96 Module have the latest Firmware updates applied:
  
      * BG96 Modem SW Revision: BG96MAR02A04M1G
      * STM32 Version: 0221 / Build: Mar 16 2018 10:08:46


# Building the samples:
There are two ways to build the Sample programs, either using the mbed command line tools (mbed CLI) or the on-line compiler at https://os.mbed.com.  As packaged in the repository, the project is configured to be build with the on-line compiler.

## On-line compiler
1. Navigate to the on-line compiler (https://os.mbed.com/compiler)
2. Select the NUCLEO-L476RG as the platform to be used
3. Select the ***'Import'*** button, then the ***'Click here'*** hyperlink to bring up the import dialog
4. Insert 'https://github.com/jflynn129/aws-iot-device-sdk-mbed-c' as the source dialog and select the ***Update all libraries to the latest revision*** check box. After performing those two steps, select the ***'Import'*** button to import the project into you on-line workspace

The program is now loaded into your on-line workspace, by default, if you press the ***'Compile'*** button, the **'Shadow_sample'** program is built. If you would like to build the **'subscribe_publish'** sample, you must perform the following steps:
1. In the **'shadow_sample'** folder, rename **'shadow_sample.cpp'** to **'shadow_sample.txt'**
2. copy the **'subscribe_publish_cpp_sample.cpp'** file from the **'subscribe_publish_cpp_sample'** foler to the **'shadow_sample'** folder
When you select ***'Compile'*** now, the **'subscribe_publish_cpp_sample.cpp'** file will be compiled and used. 

Once the program has been compiled, the executable binary file will be placed into your computers 'Downloads' folder so you can copy it to your STM32 board.

## Mbed CLI
1. Ensure you are using mbed-cli (version 1.3.0 or later)
2. Install the latest version of GNU ARM Embedded Toolchain: **https://developer.arm.com/open-source/gnu-toolchain/gnu-rm/downloads**

### Create Project
1. Import the aws-iot-device-sdk-mbed-c project: **mbed import https://github.com/jflynn129/aws-iot-device-sdk-mbed-c**

2. Edit the mbed_app.json file and remove the line that says **"ONLINE_COMPILER=1"**.  The on-line compiler uses Arm Compiler v5.06 and contains different POSIX libraries than the GNU ARM Embedded Toolchain.  Removing this line ensures the compiler includes the correct files; the JSON file is set-up to default to on-line compiling.

3. Goto the aws-iot-devices-sdk-mbed-c folder, and edit mbed_settings.py to add the path to your compiler using GCC_ARM_PATH

4. You can select which project you want to build by editing the .mbedignore file contained in the root folder. Select the desired example by commenting it out (place a # in front of the example you want to build).

### Build Application
1.  Build the program by executing **'mbed compile -t GCC_ARM -m NUCLEO_L476RG'**

2.  You can output varying amounts of debug information by removing or adding lines to the mbed_app.json file, e.g.
```
"ENABLE_IOT_INFO=1"
"ENABLE_IOT_WARN=1"
"ENABLE_IOT_ERROR=1"
```

3. Verify operation of the application program by executing it on the target hardware.  This is done by monitoring 
   the program operation using a teminal program (ex. minicom or hyperterm), with settings of 115200-N81. Program output
    should resemble the following for the shadow_sample program:

```
AWS ./examples/shadow_sample/shadow_sample.cpp Example.

AWS IoT SDK Version 3.0.0-

Shadow Init
Shadow Connect
[EasyConnect] Using BG96
[EasyConnect] Connected to Network successfully
[EasyConnect] MAC address 32:06:91:41:02:72:20
[EasyConnect] IP address 10.192.70.252

=======================================================================================

On Device: window state false
Update Shadow: {"state":{"reported":{"temperature":25.500000,"windowOpen":false}}, "clientToken":"c-sdk-client-id-0"}
*****************************************************************************************

Update Accepted !!

=======================================================================================

On Device: window state false
Update Shadow: {"state":{"reported":{"temperature":26.000000,"windowOpen":false}}, "clientToken":"c-sdk-client-id-1"}
*****************************************************************************************

Update Accepted !!

=======================================================================================

On Device: window state false
Update Shadow: {"state":{"reported":{"temperature":26.500000,"windowOpen":false}}, "clientToken":"c-sdk-client-id-2"}
*****************************************************************************************

Update Accepted !!

=======================================================================================

```
Using the  subscribe_publish_cpp_sample program, output will resemble:

```
AWS ./examples/subscribe_publish_cpp_sample/subscribe_publish_cpp_sample.cpp Example.

AWS IoT SDK Version 3.0.0-

Connecting...
[EasyConnect] Using BG96
[EasyConnect] Connected to Network successfully
[EasyConnect] MAC address 32:06:91:41:02:72:20
[EasyConnect] IP address 10.192.159.16
Subscribing...
Subscribe callback
sdkTest/sub     hello from SDK QOS0 : 0

-->yield for MQTT read

Subscribe callback
sdkTest/sub     hello from SDK QOS1 : 1
Subscribe callback
sdkTest/sub     hello from SDK QOS0 : 2

-->yield for MQTT read

Subscribe callback
sdkTest/sub     hello from SDK QOS1 : 3
Subscribe callback
sdkTest/sub     hello from SDK QOS0 : 4

-->yield for MQTT read

Subscribe callback
sdkTest/sub     hello from SDK QOS1 : 5

```

