# STM32 F2/H7 Ethernet

The provided `ecos_stm32f207_client` and `ecos_stm32h723_socket`
applications perform a simple fixed IP address, TCP socket based
connection, to transfer data between two hosts.

These are (unmodified for renode) ELF files that execute successfully
on the real, respectively STM32F2 and STM32H7. based, hardware.

Currently this repo is a **mirror** (and not a fork) of
https://github.com/renode/renode-issue-reproduction-template because
github limits users to a single fork.

The `main` branch uses the unmodified renode world, where the test
will timeout because there is no network traffic between the machines
due to missing functionality in the current baseline renode world.

The `fixed` branch provides new and updated models to allow the tests
to complete successfully. Even though the supplied ELF binaries are
IPv4 only, the fixed Ethernet models have been extensively tested with
IPv6 as well as IP4.

The fixes required (and updated models provided in the `fixed`
branch) cover:

### F2

- fix to ignore ETH_DMA0MR:FTF
- remove packetSent to allow transmission
- add IPv6 to supportedEthernetChecksums and supportedIPChecksums
- add MAC[123] functionality and match against destinationMac
- fix dmaTransmitDescriptorListBegin setting
- fix dmaReceiveDescriptorsListAddress setting

### H7

As for F2 above but with a STM32H7 RM0468 compatible model.

## branches

| Branch  | Description
|:--------|:-------------------------------------------------------------------
| `main`  | test fails to execute successfully against latest and stable renode worlds
| `fixed` | updated models to allow successful execution of the application

